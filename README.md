# DriftLock — MFA Portal (PATCHED branch)

> **This is the `patched` branch — the remediated, secure version of DriftLock.**
> All intentional vulnerabilities and the additional Red Team finding are fixed
> here. For the intentionally-vulnerable CTF target, see the `main` branch.

DriftLock is a TOTP-based multi-factor authentication portal. This branch is the
hardened build used to demonstrate remediation: each vulnerability that existed
in `main` is fixed and verified here.

---

## What differs from `main`

| Vulnerability (in `main`) | Status in `patched` |
|---|---|
| `/api/debug` info disclosure (EASY) | **Fixed** — endpoint removed; `debug=False` |
| TOTP replay (MEDIUM) | **Fixed** — reused codes rejected |
| IDOR `/api/v1/users/<id>/setup-status` (HARD) | **Fixed** — shared-secret header required (403 without it) |
| Hardcoded token in `/api/profile` (Red Team find) | **Fixed** — session-based auth |
| MASTER_KEY silent fallback (latent bug) | **Fixed** — fails closed |
| Replay detector trim bug | **Fixed** — correct memory trim |

---

## What it does

Users register (username, email, password). The server hashes the password
(bcrypt) and generates a TOTP secret, encrypted at rest (Fernet). Login requires
two factors: the password (*something you know*) and the current 6-digit code
from an authenticator app (*something you have*). TOTP protects DriftLock's own
login — one secret per user (1:1).

---

## Security controls

Password hashing (bcrypt), encrypted TOTP seeds (Fernet, fail-closed key),
two-step login with session-fixation protection, username-enumeration resistance,
Redis-backed rate limiting, account lockout, anti-enumeration password reset,
`login_required` authorization, and container hardening (non-root user, dropped
capabilities, no-new-privileges, network segmentation, localhost-only datastores).

---

## Tech stack

- Backend: Python / Flask
- Database: PostgreSQL
- Rate-limit store: Redis
- TOTP: pyotp
- Crypto: bcrypt (passwords), Fernet (TOTP seeds)
- Monitoring: Elasticsearch, Logstash, Kibana
- Mail capture: Mailpit
- Deployment: Docker Compose
- Ports: web 4325, internal-api 5000

---

## Environment (.env)

Required variables (gitignored — never commit):

```
DB_USER=driftlock_admin
DB_PASSWORD=<db password>
DB_NAME=driftlock
SECRET_KEY=<flask session key>
MASTER_KEY=<Fernet key — MUST be persistent; do not regenerate>
INTERNAL_API_KEY=<random secret for the internal-api; patched build only>
```

Generate the internal API key:
```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

> **MASTER_KEY warning:** it encrypts stored TOTP seeds. Keep the same value as
> the original deployment. In this branch the app fails to start if it is unset
> (fail-closed). Users whose seeds were encrypted under a different key must
> re-register.

---

## Running

```bash
docker compose up -d db redis web internal-api
docker compose up -d elasticsearch
# wait for elasticsearch to be healthy, then:
docker compose up -d kibana logstash
```

Endpoints: app `http://localhost:4325/`, internal-api `http://localhost:5000/`,
Kibana `http://localhost:5601/`.

---

## Verifying the fixes

```bash
# 1. Debug endpoint removed
curl -i http://localhost:4325/api/debug                       # -> 404

# 2. IDOR requires the key
curl -i http://localhost:5000/api/v1/users/2/setup-status     # -> 403 Forbidden
curl -H "X-Internal-Api-Key: <key>" \
     http://localhost:5000/api/v1/users/2/setup-status        # -> 200

# 3. Hardcoded token no longer works
curl -i -H "Authorization: Bearer valid-session-token-123" \
     http://localhost:4325/api/profile                        # -> 401

# 4. TOTP replay rejected
#    Log in with a code, log out, log in again with the SAME code within 90s
#    -> "Code already used" (was accepted on main)
```

---

## Repository structure

```
blue-team-mfa-portal/
├── docker-compose.yml
├── .env                     # secrets (gitignored)
├── README.md
├── web/                     # Flask app, auth, mfa, crypto, honeypot, detections
├── internal-api/            # separate service (IDOR endpoint, patched)
├── db/init.sql
├── elk/logstash/pipeline/   # logstash.conf
├── logs/                    # access, honeypot, internal-api, detections + captures
└── reports/
    ├── 01-design-report.md
    ├── 02-hardening-report.md
    └── 03-incident-response.md
```

---

## Reports

- `reports/01-design-report.md` — architecture, controls, vulnerability rationale,
  Wireshark findings
- `reports/02-hardening-report.md` — defense-in-depth and remediation
- `reports/03-incident-response.md` — attack evidence, detection, and fixes

---

## Notes

- All testing/scanning must occur only within the isolated lab environment.
- `.env`, `venv/`, and raw log contents must never be committed.
