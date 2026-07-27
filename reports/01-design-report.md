# 01 — Design Report

**Project:** DriftLock — Blue Team MFA Portal
**Branch:** `main` (intentionally-vulnerable CTF target)
**Exercise:** Red vs Blue Capture-the-Flag

---

## 1. Overview

DriftLock is a multi-factor authentication portal built as a deliberately-defended
target for a Red-vs-Blue exercise. It is a realistic web application secured with
genuine controls, containing three intentional, documented vulnerabilities at
increasing difficulty for the Red Team to discover, wrapped in a full detection
stack (honeypot, structured logging, and an ELK monitoring pipeline) so the Blue
Team can detect and analyze the attack.

The application runs on a non-standard port (4325), with a separate internal API
on port 5000, deployed via Docker Compose on an isolated lab network.

---

## 2. Architecture

Services orchestrated by Docker Compose:

- **web** (port 4325) — the main Flask portal: registration, two-step login
  (password + emailed OTP), session handling, rate limiting, request logging, and
  the honeypot blueprint.
- **internal-api** (port 5000) — a separate, deliberately-scannable service
  sharing the same PostgreSQL database. Hosts the IDOR endpoint.
- **db** — PostgreSQL, holding users, TOTP seeds, reset tokens, activity logs,
  and honeypot logs.
- **redis** — rate-limit counters and login-lockout tracking.
- **mailpit (MailHog)** — captures login OTP and reset email in development.
- **elasticsearch / logstash / kibana** — the ELK pipeline that ingests access,
  honeypot, and internal-api logs for triage.

### Network and exposure design
The host firewall (ufw) allows only SSH (22), the web app (4325), and the internal
API (5000) from the network. Kibana and MailHog are bound but **not exposed
externally** — they are Blue Team tooling and are reachable only on the host or via
an SSH tunnel, so the attacking team cannot see the detection dashboards or the
mail capture. This is a deliberate defense-in-depth choice.

### Authentication flow (two factors)
1. User registers; the password is hashed (bcrypt) and a TOTP secret is generated
   and encrypted at rest (Fernet).
2. At login, username/email and password are verified. On success, a one-time
   code is generated and emailed (captured by MailHog in development).
3. The user retrieves the code and submits it; on verification a full session is
   granted.

This authenticates with two factors from distinct categories — a password
(*something you know*) and an emailed one-time code (*something you receive*).

---

## 3. Security controls

- **Password hashing** — bcrypt with per-password salt.
- **TOTP seed encryption at rest** — Fernet symmetric encryption.
- **Two-step login** — password then one-time code, with a pending-session model
  so a password alone does not grant access.
- **Session-fixation protection** — the session is cleared before issuance.
- **Username-enumeration resistance** — a dummy bcrypt hash runs for unknown
  users; login returns an identical message regardless of whether the user exists.
- **Rate limiting** — Flask-Limiter (Redis-backed) on login, registration, and
  code verification.
- **Account lockout** — repeated failed logins temporarily lock the account.
- **Password reset** — token-based, with a vague response to avoid email
  enumeration.
- **Authorization** — `login_required` on sensitive routes.
- **Container hardening** — non-root application user, dropped Linux capabilities,
  `no-new-privileges`, network segmentation, and localhost-only binding of the
  database and Redis.

---

## 4. Intentional vulnerabilities (rationale)

Three vulnerabilities were planted deliberately, at increasing difficulty, each
realistic and each leaving a detectable trail. All are documented so graders
understand they are intentional; everything else is meant to be secure.

**Vulnerability 1 — EASY — Information disclosure (`/api/debug`).** An
unauthenticated endpoint leaks the Python version, platform, environment mode, and
a hint pointing at the `.env` file. Chosen as an easy, scanner-discoverable
foothold that also seeds the attack chain.

**Vulnerability 2 — MEDIUM — TOTP replay.** MFA verification does not invalidate a
code after use, so a captured code can be replayed within its window. On-theme for
an MFA portal and tests understanding of one-time-password semantics.

**Vulnerability 3 — HARD — IDOR (`/api/v1/users/<id>/setup-status`).** The internal
API returns any user's account metadata when the `id` is manipulated, with no
authorization check. Hosted on a separate scannable service so the Red Team
discovers it by port scan, then enumerates IDs. A realistic broken-access-control
challenge with a clean enumeration signature to detect.

An additional finding — a hardcoded bearer token in `/api/profile` — was
identified by the Red Team via source review. It was not one of the three primary
planted vulnerabilities and is treated as an additional finding.

---

## 5. Detection design

- **Honeypot** — `robots.txt` advertises a fake `/backup_secrets/` path; any
  request fires a CRITICAL alert. As no legitimate user visits it, honeypot hits
  are the highest-confidence indicator of compromise.
- **Access logging** — every request is logged in a structured format; scan
  bursts are recognizable by pattern.
- **Detection helpers** — TOTP replay is flagged (`mfa_replay_suspected`); IDOR
  enumeration is flagged (`idor_enumeration_suspected`, escalating to CRITICAL when
  one source reads three or more distinct IDs).
- **ELK pipeline** — Logstash ships logs into Elasticsearch; Kibana provides
  search and dashboards, allowing correlation of a single source across the
  honeypot, access, and internal-api indices.

---

## 6. Wireshark findings

Scan and legitimate traffic were captured on the lab host (single-host setup;
loopback interface). Two captures are retained in `logs/captures/`:

- **`scan_lo.pcap`** — a port scan: a single source issuing SYN packets to
  hundreds of ports within milliseconds, and on open ports completing the handshake
  then immediately sending RST with no application data.
- **`legit.pcap`** — a normal session: a full TCP handshake, a real HTTP GET, the
  server's response carrying data, and a graceful FIN close.

Annotated screenshots (`wireshark-scan-portsweep.png`,
`wireshark-openport-detection.png`, `wireshark-legitimate-traffic.png`) show the
contrast — many ports vs. one, no data vs. real data, RST vs. graceful close —
which distinguishes reconnaissance from legitimate use at the network level.

---

## 7. Summary

DriftLock combines a realistic, appropriately-hardened MFA application with three
intentional, documented vulnerabilities and a layered detection stack. The design
priorities were realism, clear intentionality (so accidental issues are
distinguishable), and detectability (every planted weakness leaves a correlatable
trail).