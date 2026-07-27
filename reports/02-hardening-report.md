# 02 — Hardening Report

**Project:** DriftLock — Blue Team MFA Portal
**Team:** Blue Team

This report describes the security implementations and defense-in-depth measures
applied to DriftLock, and the remediation applied in the patched build.

---

## 1. Defense-in-depth overview

Security is applied in layers, so that no single control is the only thing
standing between an attacker and a compromise:

1. **Network layer** — firewall rules, network segmentation, localhost-only
   binding of internal services.
2. **Container layer** — non-root user, dropped capabilities, no-new-privileges.
3. **Application layer** — authentication, authorization, input validation, rate
   limiting, secure session handling.
4. **Cryptographic layer** — password hashing, encrypted secrets at rest.
5. **Detective layer** — honeypot, structured logging, ELK monitoring.

---

## 2. Network hardening

- **Host firewall (ufw)** — default deny inbound; only SSH (22), the web app
  (4325), and the internal API (5000) are allowed. Monitoring and datastore
  ports are not exposed externally.
- **Network segmentation** — a `frontend` network for host-exposed services and
  an `internal` `backend` network (no internet access) for service-to-service
  traffic. Databases and Redis communicate only over the backend network.
- **Localhost-only datastores** — PostgreSQL and Redis host ports are bound to
  `127.0.0.1`, so they are unreachable from other machines even if the firewall
  were misconfigured.

---

## 3. Container hardening

- **Non-root user** — the web container runs as an unprivileged `appuser`, not
  root, limiting the impact of any code-execution flaw.
- **Dropped capabilities** — `cap_drop: ALL` removes all Linux capabilities from
  application containers; the app binds a high port (4325) and needs none.
- **no-new-privileges** — prevents privilege escalation via setuid binaries
  inside containers.
- **Minimal images / build hygiene** — build dependencies are installed, used,
  then purged; images are slim.

---

## 4. Application hardening

- **Two-factor authentication** — password plus TOTP, enforced in sequence via a
  pending-session model so a password alone does not grant access.
- **Session-fixation protection** — the session is cleared before a new session
  is issued on both login and MFA verification.
- **Username enumeration resistance** — a dummy bcrypt hash runs for non-existent
  users (constant-time), and login returns an identical message regardless of
  whether the username exists.
- **Rate limiting** — Redis-backed Flask-Limiter: failed logins limited
  per-username, registration and MFA verification limited per minute.
- **Account lockout** — repeated failed logins temporarily lock the account.
- **Password reset** — token-based, with a vague response that does not reveal
  whether an email is registered (anti-enumeration).
- **Authorization** — `login_required` on sensitive routes; the TOTP code
  endpoint returns only the logged-in user's own code.

---

## 5. Cryptographic hardening

- **Password hashing** — bcrypt with per-password salt; passwords are never
  stored or logged in plaintext.
- **TOTP seed encryption at rest** — seeds are encrypted with Fernet. In the
  patched build, the encryption key must be supplied via the environment and the
  application fails closed if it is missing — preventing the earlier failure mode
  where a missing key silently generated a throwaway key and rendered stored
  seeds undecryptable on restart.
- **Secrets management** — keys (`MASTER_KEY`, `SECRET_KEY`, `INTERNAL_API_KEY`)
  are supplied via environment/`.env` (gitignored), never committed to source.
  A stronger production posture would use file-based Docker secrets mounted at
  `/run/secrets/` rather than environment variables, since env vars can leak via
  process inspection.

---

## 6. Detective controls

- **Honeypot** — a fake `/backup_secrets/` path advertised via `robots.txt`;
  any access fires a CRITICAL alert. High-confidence, low-false-positive signal.
- **Structured logging** — access, honeypot, internal-api, and detection events
  are logged in parseable formats.
- **ELK monitoring** — Logstash parses and ships logs to Elasticsearch; Kibana
  provides dashboards and search for triage and source correlation.
- **Purpose-built detections** — TOTP replay and IDOR enumeration each emit
  dedicated alert events, so exploitation of the intentional vulnerabilities is
  visible even when the underlying weakness is (by design) not blocked.

---

## 7. Remediation applied in the patched build

The patched build fixes the three intentional vulnerabilities and the additional
Red Team finding:

- **Info disclosure (`/api/debug`)** — endpoint removed entirely; Flask debug
  mode disabled (`debug=False`) so the Werkzeug debugger is never exposed.
- **TOTP replay** — the MFA verification now rejects a reused code (detects *and*
  blocks), returning an error instead of granting a session.
- **IDOR (`/api/v1/users/<id>/setup-status`)** — the endpoint now requires a
  valid shared-secret header and rejects unauthorized callers with 403, blocking
  anonymous enumeration. A full production fix would additionally bind each
  request to the authenticated user's own identity.
- **Hardcoded token (`/api/profile`)** — the hardcoded bearer token was removed;
  the endpoint now authenticates via the user's session and returns only their
  own profile.
- **Supporting fixes** — the `MASTER_KEY` fallback now fails closed; the replay
  detector's memory-trim bug was corrected so detection stays reliable.

---

## 8. Residual risk and recommendations

- Run behind a production WSGI server (e.g. gunicorn) rather than the Flask
  development server.
- Enable HTTPS/TLS for all external traffic.
- Move secrets from environment variables to a secret manager or file-based
  Docker secrets.
- Enable authentication on the ELK stack (currently disabled for the lab).
- For the internal API, add per-user identity binding on top of the shared-secret
  control, and prefer unguessable identifiers over sequential integer IDs.
