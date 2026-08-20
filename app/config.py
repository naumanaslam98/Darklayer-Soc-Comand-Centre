import os


def required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(
            f"Required environment variable {name} is missing. "
            "Run scripts/generate_env.py or configure .env before starting the SOC."
        )
    return value


SOC_NAME = os.getenv("SOC_NAME", "DarkLayer SOC Center")
ADMIN_USER = os.getenv("SOC_ADMIN_USER", "admin")
ADMIN_PASSWORD = required("SOC_ADMIN_PASSWORD")
SECRET = required("SOC_SECRET")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./data/soc.db")
ENABLE_SYSLOG = os.getenv("ENABLE_SYSLOG", "true").lower() in {"1", "true", "yes", "on"}
SYSLOG_HOST = os.getenv("SYSLOG_HOST", "127.0.0.1")
SYSLOG_PORT = int(os.getenv("SYSLOG_PORT", "5514"))

# 24/7 collector authentication
AGENT_API_KEY = required("SOC_AGENT_API_KEY")

# Severe-alert email notifications (generic SMTP)
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USER)
ALERT_EMAIL_TO = os.getenv("ALERT_EMAIL_TO", "")
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "true").lower() in {"1", "true", "yes", "on"}
SMTP_USE_SSL = os.getenv("SMTP_USE_SSL", "false").lower() in {"1", "true", "yes", "on"}
EMAIL_ALERT_MIN_SEVERITY = os.getenv("EMAIL_ALERT_MIN_SEVERITY", "critical").lower()
