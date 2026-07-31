# DriftLock — MFA Portal (PATCHED branch)

> **This is the `patched` branch — the remediated, secure version of DriftLock.**
> All three intentional vulnerabilities and the additional Red Team finding are
> fixed and verified here. For the intentionally-vulnerable CTF target, see the
> `main` branch.

DriftLock is a multi-factor authentication portal. This branch is the hardened
build used to demonstrate remediation: each vulnerability that exists in `main` is
fixed and verified here.

---

## What differs from `main`

| Weakness (present in `main`) | Status in `patched` | Verified by |
|---|---|---|
| IDOR `/api/v1/users/<id>/setup-status` (EASY) | **Fixed** — shared-secret header required | no key -> 403; with key -> 200 |
| `/api/debug` info disclosure (MEDIUM) | **Fixed** — endpoint removed; `debug=False` | `curl /api/debug` -> 404 |
| Host Header Injection on `/api/reset-password` (HARD) | **Fixed** — reset URL built from a trusted base; `Host` validated against an allowlist | spoofed `Host` -> reset link uses trusted base; anomaly still logged |
| Hardcoded token in `/api/profile` (Red Team find) | **Fixed** — session-based auth | old token -> 302/401 |
| MASTER_KEY silent fallback (latent bug) | **Fixed** — fails closed | app refuses to start if unset |

---

## What it does

Users register with a username, email, and password (hashed with **bcrypt**).
At login, username/email and password are verified; on success a one-time code is
generated and emailed. In development, **MailHog / mailpit** captures the email —
the user retrieves the code and enters it to complete login. Authentication
succeeds only after both the password (*something you know*) and the emailed code
(*something you receive*) are verified.

TOTP seeds are encrypted at rest (Fernet). On this branch the encryption key must
be supplied via the environment and the app **fails closed** if it is missing.

---

## Security controls

Password hashing (bcrypt), encrypted TOTP seeds (Fernet, fail-closed key),
two-step login with session-fixation protection, username-enumeration resistance,
Redis-backed rate limiting, account lockout, anti-enumeration password reset,
trusted-base-URL construction with `Host`-header allowlisting,
`login_required` authorization, and container hardening (non-root user, dropped
capabilities, no-new-privileges, network segmentation, localhost-only datastores).

---

## Network exposure (host firewall)

The host firewall (ufw) allows only **22 (SSH), 4325 (web app), 5000
(internal-api)** from the network. **Kibana (5601) and MailHog (8025) are bound but
not exposed externally** — they are Blue Team tooling, reachable only on the host
or via an SSH tunnel, so attackers cannot view detection dashboards or captured
mail. This is deliberate.

---

## Tech stack

- Backend: Python / Flask
- Database: PostgreSQL
- Rate-limit store: Redis
- TOTP: pyotp
- Crypto: bcrypt (passwords), Fernet (TOTP seeds)
- Monitoring: Elasticsearch, Logstash, Kibana
- Mail capture: MailHog / mailpit
- Deployment: Docker Compose
- Ports: web 4325, internal-api 5000

---

## Environment (.env, gitignored)

```
DB_USER=driftlock_admin
DB_PASSWORD=<db password>
DB_NAME=driftlock
SECRET_KEY=<flask session key>
MASTER_KEY=<Fernet key — MUST be persistent; do not regenerate>
INTERNAL_API_KEY=<random secret for the internal-api; patched build only>
APP_URL=<trusted base URL for building reset links, e.g. http://localhost:4325>
EXPECTED_HOST=<allowlisted Host value, e.g. localhost:4325>
```

Generate the internal API key:
```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

> **MASTER_KEY warning:** it encrypts stored TOTP seeds. Keep the same value as the
> original deployment. On this branch the app fails to start if it is unset
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
Kibana `http://localhost:5601/` (host-only), MailHog `http://localhost:8025/`
(host-only).

---

## Verifying the fixes

```bash
# 1. IDOR requires the key (use a real user id, e.g. 3)
curl -i http://localhost:5000/api/v1/users/3/setup-status     # -> 403 Forbidden
curl -H "X-Internal-Api-Key: <key>" \
     http://localhost:5000/api/v1/users/3/setup-status        # -> 200

# 2. Debug endpoint removed
curl -i http://localhost:4325/api/debug                       # -> 404

# 3. Host Header Injection neutralised
#    A spoofed Host no longer poisons the reset link; the link is built from the
#    trusted base URL, and the anomalous Host is still logged as HOST_HEADER_ANOMALY.
curl -X POST http://localhost:4325/api/reset-password \
  -H "Host: evil-attacker.com" \
  -H "Content-Type: application/json" \
  -d '{"email": "victim@example.com"}'
#    -> emailed reset link points at the trusted base (not evil-attacker.com)

# 4. Hardcoded token no longer works
curl -i -H "Authorization: Bearer valid-session-token-123" \
     http://localhost:4325/api/profile                        # -> 302/401
```

---

