# 01 — Design Report

**Project:** DriftLock — Blue Team MFA Portal
**Team:** Blue Team
**Exercise:** Red vs Blue Capture-the-Flag

---

## 1. Overview

DriftLock is a TOTP-based multi-factor authentication portal built as a
deliberately-defended target for a Red-vs-Blue exercise. It is a realistic web
application secured with genuine controls, containing intentional, documented
vulnerabilities for the Red Team to discover, wrapped in a full detection stack
(honeypot, structured logging, and an ELK monitoring pipeline) so the Blue Team
can detect and analyze the attack.

The application runs on a non-standard port (4325), with a separate internal API
on port 5000, deployed via Docker Compose.

---

## 2. Architecture

The system is composed of the following services, orchestrated by Docker Compose:

- **web** (port 4325) — the main Flask application: registration, two-step login
  (password + TOTP), session handling, rate limiting, request logging, and the
  honeypot blueprint.
- **internal-api** (port 5000) — a separate, deliberately-exposed service sharing
  the same PostgreSQL database. Hosts the IDOR endpoint.
- **db** — PostgreSQL, holding users, TOTP seeds, reset tokens, activity logs,
  and honeypot logs.
- **redis** — backing store for rate limiting.
- **mailpit** — captures outbound email (password-reset flow) for inspection.
- **elasticsearch / logstash / kibana** — the ELK monitoring pipeline that
  ingests application, honeypot, internal-api, and detection logs for triage.

### Network design
Two Docker networks segment the system: a `frontend` network for services that
expose host ports, and an `internal` `backend` network (no internet access) for
service-to-service traffic. Database and Redis host ports are bound to localhost
only, limiting their exposure.

### Authentication flow (two-factor)
1. User registers; the server hashes the password (bcrypt) and generates a TOTP
   secret, encrypted at rest (Fernet).
2. At login, the password is verified. If MFA is enabled, the user is held in a
   pending state (`pending_mfa_user_id`) and prompted for a TOTP code.
3. The submitted code is verified against the decrypted seed. On success, a full
   session is granted.

This design authenticates with two factors from distinct categories — a password
(*something you know*) and a TOTP code from an authenticator app (*something you
have*) — satisfying the definition of MFA. TOTP here is a single login second
factor (one secret per user, a 1:1 relationship), not a multi-service vault.

---

## 3. Security controls

- **Password hashing** — bcrypt with per-password salt.
- **TOTP seed encryption** — Fernet symmetric encryption; the key is supplied via
  environment and never regenerated at runtime.
- **Session security** — sessions are cleared before issuance (session-fixation
  protection); a pending-vs-full session split ensures a password-only user is
  not logged in until the second factor is verified.
- **Username enumeration resistance** — login runs a dummy bcrypt hash for
  unknown users (constant-time behavior) and returns an identical error message
  whether the username exists or not.
- **Rate limiting** — Flask-Limiter (Redis-backed): login limited per-username on
  failed attempts, registration and MFA verification limited per minute.
- **Account lockout** — repeated failed logins lock an account temporarily.
- **Password reset** — token-based reset with a deliberately vague response
  ("if an account exists…") to avoid email enumeration.
- **Authorization** — sensitive routes require an authenticated session via a
  `login_required` decorator.
- **Container hardening** — non-root application user, dropped Linux
  capabilities, `no-new-privileges`, network segmentation, and localhost-only
  binding of internal datastores.

---

## 4. Intentional vulnerabilities (rationale)

Three vulnerabilities were planted deliberately, at increasing difficulty, each
chosen to be realistic and to leave a detectable trail. All are documented so
graders understand they are intentional; everything else in the application is
meant to be secure.

**Vulnerability 1 — EASY — Information disclosure (`/api/debug`).**
An unauthenticated endpoint leaks the Python version, platform, environment mode,
and a hint pointing at the `.env` file. Chosen as an easy, scanner-discoverable
foothold that also seeds the attack chain (the `.env` hint).

**Vulnerability 2 — MEDIUM — TOTP replay.**
The MFA verification does not invalidate a code after use, so a captured code can
be replayed within its validity window. Chosen because it is on-theme for an MFA
portal and tests understanding of one-time-password semantics.

**Vulnerability 3 — HARD — IDOR (`/api/v1/users/<id>/setup-status`).**
The internal API returns any user's account metadata when the `id` is
manipulated, with no authorization check. Hosted on a separate service so the Red
Team discovers it by port scan, then enumerates IDs. Chosen as a realistic
broken-access-control challenge with a clean enumeration signature to detect.

An additional finding — a hardcoded bearer token in `/api/profile` — was
identified by the Red Team through source review. It was not one of the three
primary planted vulnerabilities and is treated as an additional finding
(remediated in the patched build).

---

## 5. Detection design

Detection is layered so that signal can be separated from noise:

- **Honeypot** — `robots.txt` advertises a fake `/backup_secrets/` path; any
  request to it fires a CRITICAL alert. As no legitimate user visits it, honeypot
  hits are the highest-confidence indicator of compromise.
- **Access logging** — every request is logged in a structured format; scan
  bursts are recognizable by pattern.
- **Detection helpers** — TOTP replay is flagged (`mfa_replay_suspected`); IDOR
  enumeration is flagged (`idor_enumeration_suspected`, escalating to CRITICAL
  when one source reads multiple distinct IDs).
- **ELK pipeline** — Logstash ships all logs into Elasticsearch; Kibana provides
  search and dashboards, allowing correlation of a single source across the
  honeypot, access, internal-api, and detection indices.

---

## 6. Wireshark findings

Traffic was captured on the lab host (single-host setup; loopback interface).
Two contrasting patterns were documented:

- **Scan traffic** — a single source issuing bare SYN packets to hundreds of
  different ports within milliseconds, and on open ports completing the handshake
  then immediately sending RST with no application data. This is the recognizable
  reconnaissance signature.
- **Legitimate traffic** — a complete TCP handshake followed by a real HTTP GET
  request, the server's response carrying data, and a graceful FIN close.

The difference — many ports vs. one, no data vs. real data, RST vs. graceful
close — is how reconnaissance is distinguished from normal use at the network
level.

---

## 7. Summary

DriftLock combines a realistic, appropriately-hardened MFA application with three
intentional, documented vulnerabilities and a layered detection stack. The design
priorities were realism (a believable target), clear intentionality (documented
vulnerabilities so accidental issues are distinguishable), and detectability
(every planted weakness leaves a trail the Blue Team can find and correlate).
