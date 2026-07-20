# DriftLock — Blue Team MFA Portal

DriftLock is a TOTP-based multi-factor authentication portal built as the Blue
Team deliverable for a Red-vs-Blue Capture-the-Flag exercise. It is a realistic
web application, secured with genuine controls, that contains **three deliberate,
documented vulnerabilities** at increasing difficulty for the Red Team to
discover — and is wrapped in logging, a honeypot, and an ELK monitoring stack so
the Blue Team can detect and analyze the attack.

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
(Flask-Limiter, backed by Redis), session-based authentication, and a two-step
login (password then TOTP) with protections against username enumeration and
session fixation.

**2. Three intentional vulnerabilities.** The app contains three deliberate,
documented weaknesses at increasing difficulty: an unauthenticated `/api/debug`
endpoint (information disclosure), TOTP code replay (no single-use enforcement),
and an IDOR in a separate internal API (broken access control). Each is
documented below so graders understand they were deliberate; everything else is
meant to be secure.

**3. Self-monitoring / detection.** Every request is logged. A honeypot
advertises a fake `/backup_secrets/` folder via `robots.txt` and fires a CRITICAL
alert the instant anyone touches it. All logs flow through Logstash into
Elasticsearch and are visualized in Kibana, giving the Blue Team a live view for
triage and incident response.

---

## The detection loop

A single attack traces through every component:

Red Team packet -> app logs the request -> if it touches the honeypot or trips a
detection, an alert fires -> Logstash ships the log into Elasticsearch -> Kibana
surfaces it -> an analyst correlates the attacker's actions into one confirmed
incident and separates it from benign noise -> that becomes the incident-response
report.

---

## Tech stack

- **Backend:** Python / Flask
- **Database:** PostgreSQL
- **Cache / rate-limit store:** Redis
- **TOTP:** pyotp
- **Crypto:** bcrypt (passwords), Fernet (TOTP seeds)
- **Monitoring:** Elasticsearch, Logstash, Kibana (ELK)
- **Deployment:** Docker Compose
- **App port:** 4325 (web portal, non-standard per the brief)
- **Internal API port:** 5000 (internal-api — separate service, discoverable by scan)

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
docker compose up -d db redis web internal-api
```

Bring up the monitoring stack:

```bash
docker compose up -d elasticsearch
# wait for it to become healthy, then:
docker compose up -d kibana logstash
```

Key endpoints once running:

- App: `http://localhost:4325/`
- Internal API: `http://localhost:5000/`
- Kibana: `http://localhost:5601/`
- Elasticsearch: `http://localhost:9200/`

> On Linux, Elasticsearch may require: `sudo sysctl -w vm.max_map_count=262144`

### Required environment variables (.env, gitignored)

- `DB_USER`, `DB_PASSWORD`, `DB_NAME` — database credentials
- `MASTER_KEY` — Fernet key encrypting TOTP seeds at rest
- `SECRET_KEY` — Flask session signing key

---

## Repository Structure

### Current (as built)

```
blue-team-mfa-portal/
├── docker-compose.yml            # web + db + redis + internal-api + ELK
├── .env                          # secrets (gitignored)
├── .gitignore
├── README.md
│
├── web/
│   ├── app.py                    # Flask app, routes, logging, rate limiting;
│   │                             #   /api/debug = intentional vuln (EASY)
│   ├── auth.py                   # registration, login, verify-mfa, logout
│   ├── crypto_utils.py           # password hashing + TOTP seed encryption
│   ├── mfa.py                    # TOTP blueprint (totp_bp): dashboard, current-code
│   ├── decorators.py             # @login_required
│   ├── models.py                 # DB models (User, TOTPSeed, etc.)
│   ├── honeypot.py               # honeypot blueprint: robots.txt bait +
│   │                             #   /backup_secrets/ trap, embedded decoy
│   ├── robots.txt                # discloses /backup_secrets/ — bait
│   ├── requirements.txt
│   ├── Dockerfile
│   ├── templates/                # index, login, register, mfa, mfa_verify, support, admin
│   └── static/                   # css, images
│
├── internal-api/                 # separate service, own port (5000) — scannable
│   ├── api.py                    #   IDOR vuln (HARD): /api/v1/users/<id>/setup-status
│   ├── requirements.txt
│   └── Dockerfile
│
├── db/
│   └── init.sql                  # users, totp_seeds, password_reset_tokens,
│                                 #   activity_logs, honeypot_logs
│
├── elk/
│   └── logstash/
│       └── pipeline/
│           └── logstash.conf     # grok-parses access.log; JSON-parses
│                                 #   honeypot.log + internal-api.log;
│                                 #   tags /backup_secrets/ as honeypot_hit
│
├── logs/
│   ├── access.log
│   ├── honeypot.log
│   ├── internal-api.log
│   └── captures/                 # Wireshark .pcap files
│
└── reports/
    ├── 01-design-report.md
    ├── 02-hardening-report.md
    └── 03-incident-response.md
```

### Planned / target architecture

```
- web/decorators.py already provides @login_required.
  A @rate_limited helper is planned to consolidate the rate-limit
  logic currently applied inline in app.py.
```

---

## Intentional vulnerabilities (disclosure)

DriftLock contains **three** deliberate, documented vulnerabilities at increasing
difficulty. All are intentional and disclosed here for grading.

### Vulnerability 1 — EASY — Information disclosure
- **Endpoint:** `GET /api/debug` (web, port 4325)
- **Type:** Unauthenticated information disclosure
- **Exposes:** Python version, platform, environment mode, and a hint pointing at
  the `.env` file
- **Discovery:** reachable via port scan + path enumeration; no auth required
- **Detection:** access is logged at WARNING and shipped to ELK
- **Fix (production):** remove the endpoint or gate it behind authentication

### Vulnerability 2 — MEDIUM — TOTP replay
- **Location:** MFA verification flow (web, port 4325)
- **Type:** Missing one-time-use enforcement on TOTP codes
- **Exposes:** a captured code remains valid for its ~90-second window and can be
  replayed, weakening the second factor
- **Discovery:** capture a valid code and reuse it within the window
- **Detection:** verification events are logged; reuse of the same time-window
  counter for a user flags `mfa_replay_suspected`
- **Fix (production):** record consumed codes/counters and reject reuse

### Vulnerability 3 — HARD — IDOR / broken access control
- **Service:** internal-api (port 5000 — a separate, scannable service)
- **Endpoint:** `GET /api/v1/users/<id>/setup-status`
- **Type:** Insecure Direct Object Reference — returns any user's account
  metadata when the `<id>` is changed, with no authorization check
- **Exposes:** another user's username, `mfa_enabled` status, and account
  creation time
- **Discovery:** found via port scan as a second service, then path probing
  reveals the enumerable ID
- **Detection:** the service logs ID access; one source reading 3+ distinct IDs
  escalates to a CRITICAL `idor_enumeration_suspected` alert in ELK
- **Fix (production):** authenticate the caller and enforce `requested_id ==
  caller_id`, or use unguessable identifiers; do not expose internal APIs to
  untrusted networks

> **Disclosure note:** These three vulnerabilities are intentional CTF targets.
> Every other part of the application is meant to be secure — any weakness beyond
> these three is an accidental defect, not a planted target.

---

## ELK indices

- `driftlock-access-*` — all HTTP access logs (web)
- `driftlock-honeypot-*` — high-priority honeypot alerts
- `driftlock-internal-api-*` — internal-api requests + IDOR enumeration alerts

---

## Reports

- `reports/01-design-report.md` — architecture, security controls, vulnerability
  rationale, Wireshark findings
- `reports/02-hardening-report.md` — security implementations, defense-in-depth
- `reports/03-incident-response.md` — attack evidence, detection method, log
  analysis, recommended fixes

---

## Project status

**Complete:** the defensive infrastructure (honeypot, request logging, the ELK
monitoring pipeline with three indices, the internal-api service, and the Docker
deployment); the two-step login flow (password -> TOTP) with enumeration and
session-fixation protections; and session-based authorization on sensitive
endpoints. The three intentional vulnerabilities are in place and documented.

**Remaining:**
- Set `debug=False` in `app.py` for graded/demo runs.
- Harden the `MASTER_KEY` fallback to fail closed.
- Build the false-positive traffic generator for realistic triage.
- Complete the three reports and the annotated Wireshark capture.

---

## Notes

- All testing and scanning must occur **only** within the isolated lab
  environment.
- The `venv/` directory and `.env` file must never be committed.