from datetime import datetime, timedelta, timezone
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from .models import Event, Alert, IOC

SEV_RANK = {"info":0, "low":1, "medium":2, "high":3, "critical":4}

RULES = [
    {
        "id":"DL-PS-001", "title":"Suspicious PowerShell Execution", "severity":"critical",
        "tactic":"Execution", "technique":"T1059.001",
        "match": lambda e: "powershell" in (e.message or "").lower() and any(x in (e.message or "").lower() for x in ["-enc", "encodedcommand", "downloadstring", "iex ", "invoke-expression"]),
        "desc":"PowerShell command line contains high-risk execution patterns."
    },
    {
        "id":"DL-PRIV-001", "title":"Privilege Escalation Attempt", "severity":"high",
        "tactic":"Privilege Escalation", "technique":"T1548",
        "match": lambda e: any(x in (e.message or "").lower() for x in ["sudo", "runas", "sebackupprivilege", "setuid", "administrator group"]),
        "desc":"Event contains a privilege-escalation indicator."
    },
    {
        "id":"DL-EXFIL-001", "title":"Unusual Data Transfer", "severity":"high",
        "tactic":"Exfiltration", "technique":"T1041",
        "match": lambda e: (e.bytes_out or 0) >= 50 * 1024 * 1024,
        "desc":"Large outbound transfer exceeded the local SOC threshold."
    },
    {
        "id":"DL-MAL-001", "title":"Malware/Execution Indicator", "severity":"high",
        "tactic":"Execution", "technique":"T1204",
        "match": lambda e: any(x in (e.message or "").lower() for x in ["malware", "ransomware", "trojan", "mimikatz", "cobalt strike"]),
        "desc":"Known malicious tooling or malware terminology observed in telemetry."
    },
]

def make_alert(db: Session, event: Event, *, rule_id: str, title: str, severity: str,
               confidence: float, tactic: str|None, technique: str|None, description: str):
    existing = db.execute(
        select(Alert).where(Alert.event_id == event.id, Alert.rule_id == rule_id)
    ).scalar_one_or_none()
    if existing:
        return None
    alert = Alert(
        title=title, severity=severity, confidence=confidence, rule_id=rule_id,
        mitre_tactic=tactic, mitre_technique=technique,
        asset=event.asset, user=event.user, src_ip=event.src_ip, dst_ip=event.dst_ip,
        description=description, event_id=event.id,
    )
    db.add(alert); db.flush()
    return alert

def run_event_detections(db: Session, event: Event) -> list[Alert]:
    alerts: list[Alert] = []
    for rule in RULES:
        try:
            if rule["match"](event):
                a = make_alert(db, event, rule_id=rule["id"], title=rule["title"], severity=rule["severity"],
                               confidence=.88 if rule["severity"] == "critical" else .78,
                               tactic=rule["tactic"], technique=rule["technique"], description=rule["desc"])
                if a: alerts.append(a)
        except Exception:
            pass

    # IOC match against locally maintained intel store.
    candidate_pairs = [("ip", event.src_ip), ("ip", event.dst_ip), ("domain", event.domain), ("hash", event.file_hash)]
    for kind, value in candidate_pairs:
        if not value:
            continue
        ioc = db.execute(select(IOC).where(IOC.kind == kind, IOC.value == value, IOC.active == True)).scalar_one_or_none()
        if ioc:
            a = make_alert(db, event, rule_id="DL-IOC-001", title=f"Threat Intelligence IOC Match: {value}",
                           severity="critical" if ioc.confidence >= .9 else "high", confidence=ioc.confidence,
                           tactic="Command and Control", technique="T1071",
                           description=f"Telemetry matched an active {kind} IOC from {ioc.source} ({ioc.reputation}).")
            if a: alerts.append(a)

    # Brute force: 5 failed auth events by same user/src in 10 min.
    text = (event.message or "").lower()
    if event.event_type in {"auth_failure", "login_failure", "authentication_failure"} or "failed login" in text or "authentication failed" in text:
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=10)
        stmt = select(func.count(Event.id)).where(Event.ts >= cutoff)
        if event.user:
            stmt = stmt.where(Event.user == event.user)
        elif event.src_ip:
            stmt = stmt.where(Event.src_ip == event.src_ip)
        stmt = stmt.where(Event.event_type.in_(["auth_failure","login_failure","authentication_failure"]))
        count = db.execute(stmt).scalar_one() or 0
        if count >= 5:
            a = make_alert(db, event, rule_id="DL-AUTH-005", title="Brute Force Login Attempt", severity="high",
                           confidence=min(.95, .6 + count * .04), tactic="Credential Access", technique="T1110",
                           description=f"Detected {count} authentication failures within 10 minutes.")
            if a: alerts.append(a)

    # Port-scan heuristic: 12 distinct destination ports from same source in 5 min.
    if event.src_ip and event.dst_port:
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
        distinct_ports = db.execute(select(func.count(func.distinct(Event.dst_port))).where(
            Event.ts >= cutoff, Event.src_ip == event.src_ip, Event.dst_port.is_not(None)
        )).scalar_one() or 0
        if distinct_ports >= 12:
            a = make_alert(db, event, rule_id="DL-NET-012", title="Port Scan Detected", severity="medium",
                           confidence=min(.95, .65 + distinct_ports/100), tactic="Discovery", technique="T1046",
                           description=f"Source {event.src_ip} contacted {distinct_ports} distinct destination ports in 5 minutes.")
            if a: alerts.append(a)
    return alerts
