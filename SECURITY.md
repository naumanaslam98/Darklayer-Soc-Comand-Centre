# Security Policy

DarkLayer SOC Center processes security telemetry that may contain usernames, hostnames, IP addresses, process names, file paths, and other sensitive operational data.

## Supported version

Security fixes are currently applied to the latest `1.2.x` development line.

## Reporting a vulnerability

Please do **not** publish credentials, exploit details, collected telemetry, or other sensitive evidence in a public issue. Prefer a private GitHub security advisory when that feature is enabled for the repository. Otherwise, contact the repository owner privately through their GitHub profile before sharing sensitive details.

Include the affected version, reproduction steps, impact, and any proposed mitigation. Remove or redact real secrets and personal data from logs and screenshots.

## Deployment safety

- The web console binds to `127.0.0.1` by default.
- Syslog is localhost-only by default in the example configuration.
- Keep `.env`, databases, logs, API keys, SMTP credentials, and generated tokens out of Git.
- Do not expose this development build directly to the public internet.
- Use a strong generated administrator password and rotate the machine collector API key if it is exposed.
- Treat `data/soc.db` and collected raw events as sensitive security data.

## Scope note

This repository is a development SOC platform and not a certified replacement for an enterprise SIEM, EDR, or XDR product.
