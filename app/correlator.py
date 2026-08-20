from datetime import datetime, timedelta, timezone
from sqlalchemy import select
from sqlalchemy.orm import Session
from .models import Alert, Incident, IncidentAlert

SEV_RANK = {"info":0, "low":1, "medium":2, "high":3, "critical":4}
RANK_SEV = {v:k for k,v in SEV_RANK.items()}

def _incident_for_alert(db: Session, alert: Alert):
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=45)
    stmt = select(Incident).where(Incident.status.in_(["new","in_progress","on_hold"]), Incident.updated_at >= cutoff)
    if alert.asset:
        same_asset = db.execute(stmt.where(Incident.asset == alert.asset).order_by(Incident.updated_at.desc())).scalars().first()
        if same_asset: return same_asset
    if alert.user:
        same_user = db.execute(stmt.where(Incident.user == alert.user).order_by(Incident.updated_at.desc())).scalars().first()
        if same_user: return same_user
    return None

def correlate_alert(db: Session, alert: Alert) -> Incident | None:
    if SEV_RANK.get(alert.severity, 0) < 2:
        return None
    inc = _incident_for_alert(db, alert)
    if not inc:
        inc = Incident(
            title=f"{alert.title} on {alert.asset or alert.user or alert.src_ip or 'unknown entity'}",
            severity=alert.severity,
            risk_score={"medium":45,"high":70,"critical":90}.get(alert.severity,50),
            asset=alert.asset, user=alert.user,
            summary=f"Auto-created from detection {alert.rule_id}."
        )
        db.add(inc); db.flush()
    else:
        inc.updated_at = datetime.now(timezone.utc)
        inc.risk_score = min(100, inc.risk_score + {"medium":5,"high":10,"critical":18}.get(alert.severity,3))
        if SEV_RANK.get(alert.severity,0) > SEV_RANK.get(inc.severity,0):
            inc.severity = alert.severity
        inc.summary = (inc.summary or "") + f"\nCorrelated alert #{alert.id}: {alert.title}."
    link = db.execute(select(IncidentAlert).where(IncidentAlert.incident_id == inc.id, IncidentAlert.alert_id == alert.id)).scalar_one_or_none()
    if not link:
        db.add(IncidentAlert(incident_id=inc.id, alert_id=alert.id))
    db.flush()
    return inc
