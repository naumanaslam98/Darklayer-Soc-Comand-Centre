# Architecture

## Data flow

```text
macOS Unified Logs / Syslog / API / Suricata
                    |
                    v
               Collectors
                    |
                    v
             Event Ingestion API
                    |
          +---------+----------+
          |                    |
          v                    v
      SQLite Store         Event Bus
          |                    |
          |                    +----> WebSocket /ws/events
          v
    Detection Engine
          |
          v
        Alerts ---------------> WebSocket /ws/alerts
          |
          v
    Correlation Engine
          |
          v
       Incidents
          |
          +----> Dashboard / Investigation
          +----> SMTP notification (severity threshold)
```

## Main components

- **FastAPI**: REST and WebSocket API, authentication, dashboard services.
- **SQLAlchemy + SQLite**: local persistence for events, alerts, incidents, IOCs, cases, and analyst state.
- **Detection engine**: rule-based detections and MITRE ATT&CK mappings.
- **Correlation engine**: groups related alerts into incidents and calculates risk.
- **Event / alert buses**: bounded in-process live delivery to connected browsers.
- **macOS collector**: filtered Unified Log collection with persistent machine API-key authentication.
- **Syslog listener**: UDP ingestion, localhost-only by default.
- **Web UI**: dashboard, alerts, incidents, live events, threat hunting, intelligence, assets, identity, network, detections, cases, and team views.

## Current trust boundary

The repository is designed primarily for local or lab use. Public internet exposure, multi-tenant isolation, enterprise SSO/MFA, durable message queues, TLS collector transport, and production-scale search/storage are future architecture layers.
