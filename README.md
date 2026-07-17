# DriftLock — Blue Team MFA Portal

DriftLock is a TOTP-based multi-factor authentication portal built as the Blue
Team deliverable for a Red-vs-Blue Capture-the-Flag exercise. It is a realistic
web application, secured with genuine controls, that contains **one deliberate
vulnerability** for the Red Team to discover — and is wrapped in logging, a
honeypot, and an ELK monitoring stack so the Blue Team can detect and analyze the
attack.

---

## What it does

Users register an account (username, email, password). The system hashes the
password with bcrypt and generates a unique TOTP secret, which the user adds to
their authenticator app (Google Authenticator, Authy, etc.) by scanning a QR
code. Logging in then requires two factors: the password (*something you know*)
and the current six-digit code from the authenticator app (*something you have*).

TOTP here protects DriftLock's own login — one issuer, one secret per user
(a 1:1 relationship). It is a login second factor, not a multi-service
authenticator vault.

---

## How it works (the security design)

DriftLock is a **deliberately-defended target**. Three layers make that work:

**1. Realistic security controls.** Password hashing (bcrypt), encrypted TOTP
secrets (Fernet), input validation on registration, rate limiting
(Flask-Limiter, backed by Redis), and authentication on sensitive endpoints.

**2. One intentional vulnerability.** An unauthenticated `/api/debug` endpoint
leaks system information (Python version, platform, environment, a hint about the
`.env` file). This is the single planted weakness the Red Team is meant to find
through reconnaissance. It is intentional and documented here so graders
understand it was deliberate.

**3. Self-monitoring / detection.** Every request is logged. A honeypot
advertises a fake `/backup_secrets/` folder via `robots.txt` and fires a CRITICAL
alert the instant anyone touches it. All logs flow through Logstash into
Elasticsearch and are visualized in Kibana, giving the Blue Team a live view for
triage and incident response.

---

## The detection loop

A single attack traces through every component:

Red Team packet -> app logs the request -> if it touches the honeypot, a CRITICAL
alert fires -> Logstash ships the log into Elasticsearch -> Kibana surfaces it ->
an analyst correlates the attacker's actions into one confirmed incident and
separates it from benign noise -> that becomes the incident-response report.

---

## Tech stack

- **Backend:** Python / Flask
- **Database:** PostgreSQL
- **Cache / rate-limit store:** Redis
- **TOTP:** pyotp
- **Crypto:** bcrypt (passwords), Fernet (TOTP seeds)
- **Monitoring:** Elasticsearch, Logstash, Kibana (ELK)
- **Deployment:** Docker Compose
- **App port:** 4325 (non-standard, per the brief)

---

## Running the project

### Local Python (development)

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r web/requirements.txt
```

> Never commit the `venv/` directory.

### Full stack (Docker)

Bring up the application services:

```bash
docker compose up -d db redis web
```

Bring up the monitoring stack:

```bash
docker compose up -d elasticsearch
# wait for it to become healthy, then:
docker compose up -d kibana logstash
```

Key endpoints once running:

- App: `http://localhost:4325/`
- Kibana: `http://localhost:5601/`
- Elasticsearch: `http://localhost:9200/`

> On Linux, Elasticsearch may require: `sudo sysctl -w vm.max_map_count=262144`

---

## Repository Structure

### Current (as built)

```
blue-team-mfa-portal/
├── docker-compose.yml            # web + db + redis; mounts ./logs:/app/logs
├── .env                          # secrets (gitignored)
├── .gitignore
├── README.md
│
├── web/
│   ├── app.py                    # Flask app, routes, logging, rate limiting;
│   │                             #   /api/debug = intentional vuln
│   ├── auth.py                   # registration / login / password verification
│   ├── crypto_utils.py           # password hashing + TOTP seed encryption
│   ├── mfa.py                    # TOTP blueprint (totp_bp): MFA setup + verify
│   ├── models.py                 # DB models (User, etc.)
│   ├── honeypot.py               # honeypot blueprint: robots.txt bait +
│   │                             #   /backup_secrets/ trap, embedded decoy
│   ├── robots.txt                # discloses /backup_secrets/ — bait
│   ├── requirements.txt
│   ├── Dockerfile
│   ├── templates/
│   └── static/
│
├── db/
│   └── init.sql                  # users, totp_seeds, password_reset_tokens,
│                                 #   activity_logs, honeypot_logs
│
├── elk/
│   └── logstash/
│       └── pipeline/
│           └── logstash.conf     # grok-parses access.log,
│                                 #   JSON-parses honeypot.log,
│                                 #   tags /backup_secrets/ as honeypot_hit
│
├── logs/
│   ├── access.log
│   ├── honeypot.log
│   └── captures/
└── reports/
    ├── 01-design-report.md
    ├── 02-hardening-report.md
    └── 03-incident-response.md


### Planned / target architecture

Items below are part of the intended design but not yet built:

- internal-api/          # separate service; will host /api/v1/users/setup-status
                         #   (moves the intentional vuln out of web/app.py)
- web/decorators.py      # @login_required, @rate_limited helpers
```
---
---

## Intentional vulnerability (disclosure)

Per the CTF brief, DriftLock contains **one** deliberate vulnerability:

- **Endpoint:** `GET /api/debug`
- **Type:** Information disclosure (unauthenticated)
- **Exposes:** Python version, platform, environment mode, and a hint pointing at
  the `.env` file
- **Discovery:** Reachable via port scan + path enumeration; no authentication
  required

This is intentional and included so the Red Team has a realistic target to find
through reconnaissance. In production, this endpoint would be removed or gated
behind authentication.

---

## Reports

- `reports/01-design-report.md` — architecture, security controls, vulnerability
  rationale, Wireshark findings
- `reports/02-hardening-report.md` — security implementations, defense-in-depth
- `reports/03-incident-response.md` — attack evidence, detection method, log
  analysis, recommended fixes

---

## Project status

**Solid / complete:** the defensive infrastructure — honeypot, request logging,
the ELK monitoring pipeline, and the Docker deployment — is built and working.
This is the project's strongest area.

**In progress:** the login flow that chains password and TOTP is still being
built, and the application layer is being cleaned up so it ships with only its
single intentional vulnerability (`/api/debug`) and no accidental ones.

---

## Notes

- All testing and scanning must occur **only** within the isolated lab
  environment.
- The `venv/` directory and `.env` file must never be committed.
