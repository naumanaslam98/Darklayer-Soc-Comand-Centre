import asyncio, json, re
from datetime import datetime, timezone
from .db import SessionLocal
from .models import Event
from .detector import run_event_detections
from .correlator import correlate_alert
from .bus import alert_bus, event_bus

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

class SyslogProtocol(asyncio.DatagramProtocol):
    def datagram_received(self, data, addr):
        text = data.decode(errors="replace").strip()
        asyncio.create_task(self.handle(text, addr[0]))

    async def handle(self, text: str, sender: str):
        db = SessionLocal()
        try:
            lower = text.lower()
            etype = "event"
            if "failed" in lower and ("login" in lower or "auth" in lower): etype = "auth_failure"
            elif "accepted" in lower and ("ssh" in lower or "login" in lower): etype = "auth_success"
            ips = IP_RE.findall(text)
            event = Event(ts=datetime.now(timezone.utc), source="syslog", event_type=etype,
                          src_ip=ips[0] if ips else sender, message=text,
                          raw_json=json.dumps({"sender": sender, "message": text}))
            db.add(event); db.flush()
            alerts = run_event_detections(db, event)
            payloads = []
            for a in alerts:
                correlate_alert(db, a)
                payloads.append({"id":a.id,"title":a.title,"severity":a.severity,"asset":a.asset,"user":a.user})
            db.commit()
            await event_bus.publish({
                "id":event.id,"ts":event.ts.isoformat() if event.ts else None,"source":event.source,
                "event_type":event.event_type,"severity":event.severity,"asset":event.asset,"user":event.user,
                "src_ip":event.src_ip,"dst_ip":event.dst_ip,"dst_port":event.dst_port,"domain":event.domain,
                "file_hash":event.file_hash,"bytes_out":event.bytes_out,"message":event.message
            })
            for p in payloads:
                await alert_bus.publish(p)
        finally:
            db.close()

async def start_syslog(host: str, port: int):
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(lambda: SyslogProtocol(), local_addr=(host, port))
    return transport
