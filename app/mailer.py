import smtplib
from email.message import EmailMessage
from .config import (
    SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SMTP_FROM,
    ALERT_EMAIL_TO, SMTP_USE_TLS, SMTP_USE_SSL, EMAIL_ALERT_MIN_SEVERITY,
    SOC_NAME,
)

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def email_enabled() -> bool:
    return bool(SMTP_HOST and SMTP_FROM and ALERT_EMAIL_TO)


def should_email(severity: str) -> bool:
    want = SEVERITY_RANK.get(EMAIL_ALERT_MIN_SEVERITY, 4)
    return SEVERITY_RANK.get((severity or "info").lower(), 0) >= want


def send_alert_email(alert: dict) -> bool:
    if not email_enabled() or not should_email(alert.get("severity", "info")):
        return False

    sev = (alert.get("severity") or "info").upper()
    msg = EmailMessage()
    msg["Subject"] = f"[{SOC_NAME}] {sev} alert: {alert.get('title', 'Security alert')}"
    msg["From"] = SMTP_FROM
    msg["To"] = ALERT_EMAIL_TO
    msg.set_content(
        "\n".join([
            f"SOC: {SOC_NAME}",
            f"Severity: {sev}",
            f"Alert: {alert.get('title', '')}",
            f"Rule: {alert.get('rule_id', '')}",
            f"MITRE: {alert.get('mitre_tactic') or '-'} {alert.get('mitre_technique') or ''}".rstrip(),
            f"Asset: {alert.get('asset') or '-'}",
            f"User: {alert.get('user') or '-'}",
            f"Source IP: {alert.get('src_ip') or '-'}",
            f"Destination IP: {alert.get('dst_ip') or '-'}",
            f"Status: {alert.get('status') or 'new'}",
            "",
            alert.get("description") or "",
        ])
    )

    if SMTP_USE_SSL:
        smtp = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=15)
    else:
        smtp = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15)
    try:
        if SMTP_USE_TLS and not SMTP_USE_SSL:
            smtp.starttls()
        if SMTP_USER:
            smtp.login(SMTP_USER, SMTP_PASSWORD)
        smtp.send_message(msg)
        return True
    finally:
        try:
            smtp.quit()
        except Exception:
            pass
