# 02 — Hardening Report

**Project:** DriftLock — Blue Team MFA Portal
**Branch:** `main` (intentionally-vulnerable CTF target)

This report describes the security implementations and defense-in-depth measures
applied to DriftLock.

---

## 1. Defense-in-depth overview

Security is applied in layers so no single control is the only barrier:

1. **Network layer** — host firewall, network segmentation, localhost-only
   binding of internal services.
2. **Container layer** — non-root user, dropped capabilities, no-new-privileges.
3. **Application layer** — authentication, authorization, input validation, rate
   limiting, secure session handling.
4. **Cryptographic layer** — password hashing, encrypted secrets at rest.
5. **Detective layer** — honeypot, structured logging, ELK monitoring.

---

## 2. Network hardening

- **Host firewall (ufw)** — default deny inbound; only SSH (22), the web app
  (4325), and the internal API (5000) are allowed from the network.
- **Monitoring tooling not exposed** — Kibana (5601) and MailHog (8025) are bound
  but firewalled from external access. They are reachable only on the host or via
  an SSH tunnel, so the attacking team cannot view the detection dashboards or the
  captured mail. This is deliberate: monitoring is a Blue Team asset and is not
  part of the intended attack surface.
- **Network segmentation** — a `frontend` network for host-exposed services and an
  `internal` `backend` network (no internet access) for service-to-service
  traffic. Databases and Redis communicate only over the backend network.
- **Localhost-only datastores** — PostgreSQL and Redis host ports are bound to
  `127.0.0.1`, unreachable from other machines even if the firewall were
  misconfigured.

---

## 3. Container hardening

- **Non-root user** — the web container runs as an unprivileged `appuser`.
- **Dropped capabilities** — `cap_drop: ALL` removes all Linux capabilities from
  application containers; the app binds a high port and needs none.
- **no-new-privileges** — prevents privilege escalation via setuid binaries.
- **Minimal images** — build dependencies are installed, used, then purged.

---

## 4. Application, cryptographic, and detective controls

**Application:** two-factor login (password + emailed OTP) enforced in sequence via
a pending-session model; session-fixation protection; username-enumeration
resistance (constant-time dummy hash, identical error messages); Redis-backed rate
limiting; account lockout; anti-enumeration password reset; `login_required`
authorization on sensitive routes.

**Cryptographic:** bcrypt password hashing with per-password salt; Fernet
encryption of TOTP seeds at rest; secrets supplied via environment/`.env`
(gitignored), never committed.

**Detective:** honeypot (`/backup_secrets/` via `robots.txt`) firing CRITICAL
alerts; structured access/honeypot/internal-api logging; ELK pipeline for triage
and single-source correlation; purpose-built TOTP-replay and IDOR-enumeration
detections.

---

## 5. Known / accepted items (this branch)

This `main` branch is the intentionally-vulnerable CTF target. In addition to the
three documented intentional vulnerabilities, the following are present as
accepted items on this branch and are addressed on the `patched` branch:

- **Flask debug mode** — `debug=True` is set for development convenience; it
  exposes the Werkzeug debugger and should be disabled for any graded/production
  run. (Fixed on `patched`.)
- **`MASTER_KEY` fallback** — if unset, the app would generate a throwaway key,
  which would render stored TOTP seeds undecryptable on restart. (Fixed on
  `patched` to fail closed.)

---

## 6. Residual risk and recommendations

- Run behind a production WSGI server (e.g. gunicorn) rather than the Flask
  development server.
- Enable HTTPS/TLS for all external traffic.
- Move secrets from environment variables to a secret manager or file-based Docker
  secrets.
- Enable authentication on the ELK stack (disabled for the lab).
- For the internal API, add per-user identity binding and prefer unguessable
  identifiers over sequential integer IDs.