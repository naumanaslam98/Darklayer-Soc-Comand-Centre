import asyncio, json, os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select, func, desc, or_
from sqlalchemy.orm import Session

from .config import SOC_NAME, ENABLE_SYSLOG, SYSLOG_HOST, SYSLOG_PORT
from .db import Base, engine, get_db, SessionLocal
from .models import Event, Alert, Incident, IncidentAlert, IOC, Case, Analyst
from .schemas import LoginIn, EventIn, IOCIn, CaseIn
from .auth import verify_login, create_token, require_auth, verify_token, require_agent_key
from .detector import run_event_detections
from .correlator import correlate_alert
from .bus import alert_bus, event_bus
from .syslog_server import start_syslog
from .mailer import send_alert_email

APP_DIR = Path(__file__).resolve().parent
STATIC_DIR = APP_DIR / "static"
app = FastAPI(title=SOC_NAME, version="1.2.0")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
_syslog_transport = None

@app.on_event("startup")
async def startup():
    global _syslog_transport
    Path("data").mkdir(exist_ok=True)
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        if db.execute(select(func.count(Analyst.id))).scalar_one() == 0:
            for name, tier in [("Alex Morgan","Tier 2"),("Riya Patel","Tier 2"),("Taylor Johnson","Tier 1"),("Morgan Lee","Tier 1")]:
                db.add(Analyst(name=name, tier=tier))
            db.commit()
    finally:
        db.close()
    if ENABLE_SYSLOG:
        try:
            _syslog_transport = await start_syslog(SYSLOG_HOST, SYSLOG_PORT)
        except OSError as exc:
            print(f"SYSLOG listener not started: {exc}")

@app.on_event("shutdown")
async def shutdown():
    if _syslog_transport:
        _syslog_transport.close()

@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")

@app.get("/api/health")
def health():
    return {"ok": True, "name": SOC_NAME, "version": "1.2.0", "syslog": ENABLE_SYSLOG, "syslog_port": SYSLOG_PORT}

@app.post("/api/login")
def login(payload: LoginIn):
    if not verify_login(payload.username, payload.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"token": create_token(payload.username), "user": payload.username, "soc_name": SOC_NAME}

def event_to_dict(e: Event, include_raw: bool = False):
    out = {"id":e.id,"ts":e.ts.isoformat() if e.ts else None,"source":e.source,"event_type":e.event_type,"severity":e.severity,
           "asset":e.asset,"user":e.user,"src_ip":e.src_ip,"dst_ip":e.dst_ip,"dst_port":e.dst_port,"domain":e.domain,
           "file_hash":e.file_hash,"bytes_out":e.bytes_out,"message":e.message}
    if include_raw:
        try:
            out["raw"] = json.loads(e.raw_json or "{}")
        except Exception:
            out["raw"] = {"raw_text": e.raw_json or ""}
    return out

def alert_to_dict(a: Alert):
    return {"id":a.id,"created_at":a.created_at.isoformat() if a.created_at else None,"title":a.title,"severity":a.severity,
            "confidence":a.confidence,"rule_id":a.rule_id,"mitre_tactic":a.mitre_tactic,"mitre_technique":a.mitre_technique,
            "asset":a.asset,"user":a.user,"src_ip":a.src_ip,"dst_ip":a.dst_ip,"status":a.status,"analyst":a.analyst,
            "description":a.description,"event_id":a.event_id}

def incident_to_dict(i: Incident, alert_count=0):
    return {"id":i.id,"created_at":i.created_at.isoformat() if i.created_at else None,"updated_at":i.updated_at.isoformat() if i.updated_at else None,
            "title":i.title,"severity":i.severity,"status":i.status,"risk_score":i.risk_score,"asset":i.asset,"user":i.user,
            "owner":i.owner,"summary":i.summary,"alert_count":alert_count}

async def _ingest_event_payload(payload: EventIn, db: Session):
    e = Event(ts=payload.ts or datetime.now(timezone.utc), source=payload.source, event_type=payload.event_type,
              severity=payload.severity.lower(), asset=payload.asset, user=payload.user, src_ip=payload.src_ip, dst_ip=payload.dst_ip,
              dst_port=payload.dst_port, domain=payload.domain, file_hash=payload.file_hash, bytes_out=payload.bytes_out,
              message=payload.message, raw_json=json.dumps(payload.raw))
    db.add(e); db.flush()
    alerts = run_event_detections(db, e)
    incidents=[]
    for a in alerts:
        inc = correlate_alert(db, a)
        if inc: incidents.append(inc.id)
    db.commit()
    event_payload = event_to_dict(e)
    await event_bus.publish(event_payload)
    out = [alert_to_dict(a) for a in alerts]
    for a in out:
        await alert_bus.publish(a)
        # SMTP is blocking I/O; keep the event pipeline responsive.
        asyncio.create_task(asyncio.to_thread(_safe_email_alert, a))
    return {"event":event_payload,"alerts":out,"incident_ids":incidents}

def _safe_email_alert(alert: dict):
    try:
        send_alert_email(alert)
    except Exception as exc:
        print(f"ALERT EMAIL FAILED: {exc}")

@app.post("/api/events")
async def ingest_event(payload: EventIn, db: Session = Depends(get_db), _: str = Depends(require_auth)):
    return await _ingest_event_payload(payload, db)

@app.post("/api/agent/events")
async def ingest_agent_event(payload: EventIn, db: Session = Depends(get_db), _: str = Depends(require_agent_key)):
    return await _ingest_event_payload(payload, db)

@app.post("/api/ingest/file")
async def ingest_file(file: UploadFile = File(...), db: Session = Depends(get_db), _: str = Depends(require_auth)):
    raw = await file.read()
    if len(raw) > 25 * 1024 * 1024:
        raise HTTPException(413, "File too large; local limit is 25 MB")
    text = raw.decode(errors="replace")
    created_events=0; created_alerts=0; payloads=[]; event_payloads=[]
    for line in text.splitlines()[:10000]:
        line=line.strip()
        if not line: continue
        data={}
        try:
            data=json.loads(line)
        except Exception:
            data={"message":line}
        msg=str(data.get("message") or data.get("msg") or line)
        etype=str(data.get("event_type") or "event")
        lower=msg.lower()
        if "failed" in lower and ("login" in lower or "auth" in lower): etype="auth_failure"
        e=Event(ts=datetime.now(timezone.utc), source=str(data.get("source") or file.filename or "file"), event_type=etype,
                severity=str(data.get("severity") or "info").lower(), asset=data.get("asset") or data.get("host") or data.get("hostname"),
                user=data.get("user") or data.get("username"), src_ip=data.get("src_ip") or data.get("source_ip"),
                dst_ip=data.get("dst_ip") or data.get("destination_ip"), dst_port=data.get("dst_port"), domain=data.get("domain"),
                file_hash=data.get("file_hash") or data.get("hash"), bytes_out=data.get("bytes_out"), message=msg, raw_json=json.dumps(data))
        db.add(e); db.flush(); created_events += 1; event_payloads.append(event_to_dict(e))
        alerts=run_event_detections(db,e)
        for a in alerts:
            correlate_alert(db,a); payloads.append(alert_to_dict(a)); created_alerts += 1
    db.commit()
    # A large uploaded file should not overwhelm live browsers; stream the newest tail.
    for e in event_payloads[-500:]: await event_bus.publish(e)
    for p in payloads[-100:]: await alert_bus.publish(p)
    return {"events":created_events,"alerts":created_alerts}

@app.get("/api/dashboard")
def dashboard(db: Session = Depends(get_db), _: str = Depends(require_auth)):
    now=datetime.now(timezone.utc); since=now-timedelta(hours=24)
    active_alerts=db.execute(select(func.count(Alert.id)).where(Alert.status != "closed")).scalar_one()
    critical_incidents=db.execute(select(func.count(Incident.id)).where(Incident.status != "closed", Incident.severity=="critical")).scalar_one()
    open_incidents=db.execute(select(func.count(Incident.id)).where(Incident.status != "closed")).scalar_one()
    total_events=db.execute(select(func.count(Event.id)).where(Event.ts>=since)).scalar_one()
    assets_at_risk=db.execute(select(func.count(func.distinct(Alert.asset))).where(Alert.status != "closed", Alert.asset.is_not(None))).scalar_one()
    users_at_risk=db.execute(select(func.count(func.distinct(Alert.user))).where(Alert.status != "closed", Alert.user.is_not(None))).scalar_one()
    sev_rows=db.execute(select(Alert.severity,func.count(Alert.id)).where(Alert.created_at>=since).group_by(Alert.severity)).all()
    severity={k:v for k,v in sev_rows}
    # 12 two-hour buckets
    buckets=[]
    for idx in range(11,-1,-1):
        start=now-timedelta(hours=(idx+1)*2); end=now-timedelta(hours=idx*2)
        c=db.execute(select(func.count(Alert.id)).where(Alert.created_at>=start,Alert.created_at<end)).scalar_one()
        buckets.append({"label":start.astimezone().strftime("%H:%M"),"value":c})
    tactics=db.execute(select(Alert.mitre_tactic,func.count(Alert.id)).where(Alert.mitre_tactic.is_not(None)).group_by(Alert.mitre_tactic).order_by(desc(func.count(Alert.id)))).all()
    top_assets=db.execute(select(Alert.asset,func.count(Alert.id)).where(Alert.asset.is_not(None)).group_by(Alert.asset).order_by(desc(func.count(Alert.id))).limit(6)).all()
    analysts=db.execute(select(Analyst)).scalars().all()
    workloads=[]
    for an in analysts:
        c=db.execute(select(func.count(Alert.id)).where(Alert.analyst==an.name,Alert.status!="closed")).scalar_one()
        workloads.append({"name":an.name,"tier":an.tier,"open":c,"status":an.status})
    recent=db.execute(select(Alert).order_by(Alert.created_at.desc()).limit(10)).scalars().all()
    return {
        "metrics":{"active_alerts":active_alerts,"critical_incidents":critical_incidents,"open_incidents":open_incidents,
                   "events_24h":total_events,"assets_at_risk":assets_at_risk,"users_at_risk":users_at_risk},
        "severity":severity,"alert_trend":buckets,
        "tactics":[{"name":k or "Unknown","count":v} for k,v in tactics],
        "top_assets":[{"name":k or "Unknown","count":v} for k,v in top_assets],
        "workload":workloads,"recent_alerts":[alert_to_dict(a) for a in recent]
    }

@app.get("/api/alerts")
def list_alerts(status: Optional[str]=None, severity: Optional[str]=None, q: Optional[str]=None,
                limit:int=Query(100,ge=1,le=500), db: Session=Depends(get_db), _:str=Depends(require_auth)):
    stmt=select(Alert)
    if status: stmt=stmt.where(Alert.status==status)
    if severity: stmt=stmt.where(Alert.severity==severity)
    if q:
        s=f"%{q}%"; stmt=stmt.where(or_(Alert.title.ilike(s),Alert.asset.ilike(s),Alert.user.ilike(s),Alert.src_ip.ilike(s),Alert.rule_id.ilike(s)))
    items=db.execute(stmt.order_by(Alert.created_at.desc()).limit(limit)).scalars().all()
    return [alert_to_dict(a) for a in items]

@app.patch("/api/alerts/{alert_id}")
def update_alert(alert_id:int, payload:dict, db:Session=Depends(get_db), _:str=Depends(require_auth)):
    a=db.get(Alert,alert_id)
    if not a: raise HTTPException(404,"Alert not found")
    if "status" in payload and payload["status"] in {"new","in_progress","on_hold","closed"}: a.status=payload["status"]
    if "analyst" in payload: a.analyst=payload["analyst"] or None
    db.commit(); return alert_to_dict(a)

@app.get("/api/incidents")
def list_incidents(db:Session=Depends(get_db), _:str=Depends(require_auth)):
    items=db.execute(select(Incident).order_by(Incident.updated_at.desc()).limit(200)).scalars().all()
    out=[]
    for i in items:
        c=db.execute(select(func.count(IncidentAlert.id)).where(IncidentAlert.incident_id==i.id)).scalar_one()
        out.append(incident_to_dict(i,c))
    return out

@app.get("/api/incidents/{incident_id}")
def incident_detail(incident_id:int, db:Session=Depends(get_db), _:str=Depends(require_auth)):
    i=db.get(Incident,incident_id)
    if not i: raise HTTPException(404,"Incident not found")
    alert_ids=db.execute(select(IncidentAlert.alert_id).where(IncidentAlert.incident_id==incident_id)).scalars().all()
    alerts=db.execute(select(Alert).where(Alert.id.in_(alert_ids)).order_by(Alert.created_at)).scalars().all() if alert_ids else []
    return {"incident":incident_to_dict(i,len(alerts)),"alerts":[alert_to_dict(a) for a in alerts]}

@app.patch("/api/incidents/{incident_id}")
def update_incident(incident_id:int,payload:dict,db:Session=Depends(get_db),_:str=Depends(require_auth)):
    i=db.get(Incident,incident_id)
    if not i: raise HTTPException(404,"Incident not found")
    if "status" in payload and payload["status"] in {"new","in_progress","on_hold","closed"}: i.status=payload["status"]
    if "owner" in payload: i.owner=payload["owner"] or None
    if "summary" in payload: i.summary=str(payload["summary"])
    i.updated_at=datetime.now(timezone.utc); db.commit(); return incident_to_dict(i)

@app.get("/api/events/recent")
def recent_events(source: Optional[str]=None, event_type: Optional[str]=None, severity: Optional[str]=None, q: Optional[str]=None,
                  limit:int=Query(250,ge=1,le=1000), db:Session=Depends(get_db), _:str=Depends(require_auth)):
    stmt=select(Event)
    if source: stmt=stmt.where(Event.source==source)
    if event_type: stmt=stmt.where(Event.event_type==event_type)
    if severity: stmt=stmt.where(Event.severity==severity)
    if q:
        term=f"%{q}%"
        stmt=stmt.where(or_(Event.message.ilike(term),Event.asset.ilike(term),Event.user.ilike(term),Event.src_ip.ilike(term),Event.dst_ip.ilike(term),Event.source.ilike(term),Event.event_type.ilike(term)))
    items=db.execute(stmt.order_by(Event.ts.desc()).limit(limit)).scalars().all()
    return [event_to_dict(e) for e in items]

@app.get("/api/events/{event_id}")
def event_detail(event_id:int, db:Session=Depends(get_db), _:str=Depends(require_auth)):
    e=db.get(Event,event_id)
    if not e: raise HTTPException(404,"Event not found")
    alerts=db.execute(select(Alert).where(Alert.event_id==event_id).order_by(Alert.created_at.desc())).scalars().all()
    return {"event":event_to_dict(e,include_raw=True),"alerts":[alert_to_dict(a) for a in alerts]}

@app.get("/api/live/stats")
def live_stats(db:Session=Depends(get_db), _:str=Depends(require_auth)):
    now=datetime.now(timezone.utc)
    minute=now-timedelta(minutes=1); five=now-timedelta(minutes=5); day=now-timedelta(hours=24)
    return {
        "events_last_minute":db.execute(select(func.count(Event.id)).where(Event.ts>=minute)).scalar_one(),
        "events_last_5m":db.execute(select(func.count(Event.id)).where(Event.ts>=five)).scalar_one(),
        "events_24h":db.execute(select(func.count(Event.id)).where(Event.ts>=day)).scalar_one(),
        "alerts_last_minute":db.execute(select(func.count(Alert.id)).where(Alert.created_at>=minute)).scalar_one(),
        "critical_open":db.execute(select(func.count(Alert.id)).where(Alert.severity=="critical",Alert.status!="closed")).scalar_one(),
        "last_event":(lambda x: event_to_dict(x) if x else None)(db.execute(select(Event).order_by(Event.ts.desc()).limit(1)).scalar_one_or_none()),
    }

@app.get("/api/hunt")
def hunt(q:Optional[str]=None,user:Optional[str]=None,asset:Optional[str]=None,src_ip:Optional[str]=None,
         event_type:Optional[str]=None,limit:int=Query(200,ge=1,le=1000),db:Session=Depends(get_db),_:str=Depends(require_auth)):
    stmt=select(Event)
    if q:
        s=f"%{q}%"; stmt=stmt.where(or_(Event.message.ilike(s),Event.domain.ilike(s),Event.asset.ilike(s),Event.user.ilike(s),Event.src_ip.ilike(s),Event.dst_ip.ilike(s)))
    if user: stmt=stmt.where(Event.user==user)
    if asset: stmt=stmt.where(Event.asset==asset)
    if src_ip: stmt=stmt.where(Event.src_ip==src_ip)
    if event_type: stmt=stmt.where(Event.event_type==event_type)
    items=db.execute(stmt.order_by(Event.ts.desc()).limit(limit)).scalars().all()
    return [event_to_dict(e) for e in items]

@app.get("/api/iocs")
def list_iocs(db:Session=Depends(get_db),_:str=Depends(require_auth)):
    return [{"id":i.id,"kind":i.kind,"value":i.value,"reputation":i.reputation,"confidence":i.confidence,"source":i.source,"active":i.active,"notes":i.notes} for i in db.execute(select(IOC).order_by(IOC.created_at.desc())).scalars().all()]

@app.post("/api/iocs")
def add_ioc(payload:IOCIn,db:Session=Depends(get_db),_:str=Depends(require_auth)):
    if payload.kind not in {"ip","domain","hash"}: raise HTTPException(400,"kind must be ip, domain or hash")
    existing=db.execute(select(IOC).where(IOC.value==payload.value)).scalar_one_or_none()
    if existing: raise HTTPException(409,"IOC already exists")
    i=IOC(**payload.model_dump()); db.add(i); db.commit(); db.refresh(i)
    return {"id":i.id,"kind":i.kind,"value":i.value,"confidence":i.confidence}

@app.post("/api/cases")
def add_case(payload:CaseIn,db:Session=Depends(get_db),_:str=Depends(require_auth)):
    c=Case(**payload.model_dump()); db.add(c); db.commit(); db.refresh(c)
    return {"id":c.id,"title":c.title,"status":c.status,"priority":c.priority,"owner":c.owner}

@app.get("/api/cases")
def list_cases(db:Session=Depends(get_db),_:str=Depends(require_auth)):
    items=db.execute(select(Case).order_by(Case.created_at.desc())).scalars().all()
    return [{"id":c.id,"title":c.title,"status":c.status,"priority":c.priority,"owner":c.owner,"incident_id":c.incident_id,"notes":c.notes,
             "created_at":c.created_at.isoformat() if c.created_at else None} for c in items]

@app.get("/api/analysts")
def analysts(db:Session=Depends(get_db),_:str=Depends(require_auth)):
    return [{"id":a.id,"name":a.name,"tier":a.tier,"status":a.status} for a in db.execute(select(Analyst).order_by(Analyst.name)).scalars().all()]


@app.get("/api/sources")
def sources(db:Session=Depends(get_db),_:str=Depends(require_auth)):
    rows=db.execute(select(Event.source,func.count(Event.id),func.max(Event.ts)).group_by(Event.source).order_by(desc(func.count(Event.id)))).all()
    return [{"source":src or "unknown","events":count,"last_seen":last.isoformat() if last else None} for src,count,last in rows]

@app.get("/api/assets")
def assets(db:Session=Depends(get_db),_:str=Depends(require_auth)):
    names=db.execute(select(Event.asset).where(Event.asset.is_not(None)).distinct().limit(500)).scalars().all()
    out=[]
    for name in names:
        ec=db.execute(select(func.count(Event.id)).where(Event.asset==name)).scalar_one()
        ac=db.execute(select(func.count(Alert.id)).where(Alert.asset==name)).scalar_one()
        crit=db.execute(select(func.count(Alert.id)).where(Alert.asset==name,Alert.severity=="critical",Alert.status!="closed")).scalar_one()
        last=db.execute(select(func.max(Event.ts)).where(Event.asset==name)).scalar_one()
        risk=min(100,crit*30+ac*6)
        out.append({"asset":name,"events":ec,"alerts":ac,"critical_open":crit,"risk_score":risk,"last_seen":last.isoformat() if last else None})
    return sorted(out,key=lambda x:(x["risk_score"],x["alerts"]),reverse=True)

@app.get("/api/identities")
def identities(db:Session=Depends(get_db),_:str=Depends(require_auth)):
    names=db.execute(select(Event.user).where(Event.user.is_not(None)).distinct().limit(500)).scalars().all()
    out=[]
    for name in names:
        ec=db.execute(select(func.count(Event.id)).where(Event.user==name)).scalar_one()
        ac=db.execute(select(func.count(Alert.id)).where(Alert.user==name)).scalar_one()
        failed=db.execute(select(func.count(Event.id)).where(Event.user==name,Event.event_type.in_(["auth_failure","login_failure","authentication_failure"]))).scalar_one()
        last=db.execute(select(func.max(Event.ts)).where(Event.user==name)).scalar_one()
        risk=min(100,ac*10+min(40,failed*4))
        out.append({"user":name,"events":ec,"alerts":ac,"failed_auth":failed,"risk_score":risk,"last_seen":last.isoformat() if last else None})
    return sorted(out,key=lambda x:x["risk_score"],reverse=True)

@app.get("/api/network/summary")
def network_summary(db:Session=Depends(get_db),_:str=Depends(require_auth)):
    src=db.execute(select(Event.src_ip,func.count(Event.id)).where(Event.src_ip.is_not(None)).group_by(Event.src_ip).order_by(desc(func.count(Event.id))).limit(20)).all()
    dst=db.execute(select(Event.dst_ip,func.count(Event.id)).where(Event.dst_ip.is_not(None)).group_by(Event.dst_ip).order_by(desc(func.count(Event.id))).limit(20)).all()
    ports=db.execute(select(Event.dst_port,func.count(Event.id)).where(Event.dst_port.is_not(None)).group_by(Event.dst_port).order_by(desc(func.count(Event.id))).limit(20)).all()
    transfers=db.execute(select(Event).where(Event.bytes_out.is_not(None)).order_by(Event.bytes_out.desc()).limit(20)).scalars().all()
    return {"top_sources":[{"name":k,"count":v} for k,v in src],"top_destinations":[{"name":k,"count":v} for k,v in dst],
            "top_ports":[{"name":str(k),"count":v} for k,v in ports],"transfers":[event_to_dict(e) for e in transfers]}

@app.get("/api/detections")
def detections(db:Session=Depends(get_db),_:str=Depends(require_auth)):
    from .detector import RULES
    base=[{"rule_id":r["id"],"title":r["title"],"severity":r["severity"],"tactic":r["tactic"],"technique":r["technique"]} for r in RULES]
    base += [
      {"rule_id":"DL-IOC-001","title":"Threat Intelligence IOC Match","severity":"high/critical","tactic":"Command and Control","technique":"T1071"},
      {"rule_id":"DL-AUTH-005","title":"Brute Force Login Attempt","severity":"high","tactic":"Credential Access","technique":"T1110"},
      {"rule_id":"DL-NET-012","title":"Port Scan Detected","severity":"medium","tactic":"Discovery","technique":"T1046"},
    ]
    out=[]
    for r in base:
        c=db.execute(select(func.count(Alert.id)).where(Alert.rule_id==r["rule_id"])).scalar_one()
        last=db.execute(select(func.max(Alert.created_at)).where(Alert.rule_id==r["rule_id"])).scalar_one()
        out.append({**r,"fires":c,"last_fired":last.isoformat() if last else None,"health":"healthy"})
    return out

@app.post("/api/demo/generate")
async def demo_generate(db:Session=Depends(get_db),_:str=Depends(require_auth)):
    samples=[
      EventIn(source="EDR",event_type="process_creation",asset="WS-10234",user="jdoe",src_ip="10.0.2.14",message="powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"),
      EventIn(source="IAM",event_type="auth_failure",asset="VPN-GW-01",user="mrichards",src_ip="193.231.78.12",message="Failed login for mrichards"),
      EventIn(source="EDR",event_type="privilege_change",asset="WS-88021",user="svc_backup",message="sudo administrator group membership changed"),
      EventIn(source="DLP",event_type="network_transfer",asset="FILE-SRV-02",user="bthomas",dst_ip="45.142.120.63",bytes_out=120*1024*1024,message="Outbound archive transfer"),
    ]
    # Seed IOC so one event will match on subsequent generation.
    if not db.execute(select(IOC).where(IOC.value=="45.142.120.63")).scalar_one_or_none():
        db.add(IOC(kind="ip",value="45.142.120.63",confidence=.94,source="Local SOC Intel",notes="Demo C2 indicator")); db.flush()
    payloads=[]; demo_events=[]
    for p in samples:
        e=Event(ts=datetime.now(timezone.utc),source=p.source,event_type=p.event_type,severity=p.severity,asset=p.asset,user=p.user,
                src_ip=p.src_ip,dst_ip=p.dst_ip,dst_port=p.dst_port,domain=p.domain,file_hash=p.file_hash,bytes_out=p.bytes_out,message=p.message,raw_json="{}")
        db.add(e); db.flush(); demo_events.append(event_to_dict(e))
        for a in run_event_detections(db,e):
            correlate_alert(db,a); payloads.append(alert_to_dict(a))
    # Create enough auth failures to exercise brute-force rule.
    for n in range(6):
        e=Event(ts=datetime.now(timezone.utc),source="IAM",event_type="auth_failure",asset="VPN-GW-01",user="jdoe",src_ip="203.0.113.50",message="Failed login for jdoe",raw_json="{}")
        db.add(e); db.flush(); demo_events.append(event_to_dict(e))
        for a in run_event_detections(db,e):
            correlate_alert(db,a); payloads.append(alert_to_dict(a))
    # Port scan heuristic.
    for port in [21,22,23,25,53,80,110,135,139,443,445,3389,8080]:
        e=Event(ts=datetime.now(timezone.utc),source="NDR",event_type="network_connection",asset="EDGE-FW-01",src_ip="198.51.100.77",dst_ip="10.0.0.10",dst_port=port,message=f"Connection to port {port}",raw_json="{}")
        db.add(e); db.flush(); demo_events.append(event_to_dict(e))
        for a in run_event_detections(db,e):
            correlate_alert(db,a); payloads.append(alert_to_dict(a))
    db.commit()
    for e in demo_events: await event_bus.publish(e)
    for p in payloads: await alert_bus.publish(p)
    return {"generated":True,"alerts":len(payloads)}

@app.websocket("/ws/alerts")
async def ws_alerts(ws:WebSocket, token:str=Query(...)):
    try: verify_token(token)
    except Exception:
        await ws.close(code=4401); return
    await ws.accept(); q=alert_bus.subscribe()
    try:
        while True:
            item=await q.get(); await ws.send_json(item)
    except WebSocketDisconnect:
        pass
    finally:
        alert_bus.unsubscribe(q)


@app.websocket("/ws/events")
async def ws_events(ws:WebSocket, token:str=Query(...)):
    try: verify_token(token)
    except Exception:
        await ws.close(code=4401); return
    await ws.accept(); q=event_bus.subscribe()
    try:
        while True:
            item=await q.get(); await ws.send_json(item)
    except WebSocketDisconnect:
        pass
    finally:
        event_bus.unsubscribe(q)
