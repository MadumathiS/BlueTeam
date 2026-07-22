# 01 — Design Report

**Project:** DriftLock — Blue Team MFA Portal
**Exercise:** Red vs. Blue Capture-the-Flag
**Team role:** Blue Team (Defenders / Web Developers)

---

## 1. Overview

DriftLock is a TOTP-based multi-factor authentication portal. It presents a
realistic, genuinely-defended web application that also contains three
deliberate, documented vulnerabilities at increasing difficulty for the Red Team
to discover. The whole system is wrapped in request logging, a honeypot, and an
ELK monitoring stack so the Blue Team can detect and reconstruct the attack.

The design goal was a target that is *hard enough to be interesting* — real
password hashing, encrypted secrets, rate limiting, two-step login — so that the
planted weaknesses have to be found through reconnaissance rather than handed
over. Everything outside the three disclosed vulnerabilities is intended to be
secure.

## 2. Architecture

### 2.1 Services

| Service       | Port  | Role                                                        |
|---------------|-------|-------------------------------------------------------------|
| web (Flask)   | 4325  | Main portal: registration, login, MFA, support, honeypot    |
| internal-api  | 5000  | Separate, scannable service — hosts the IDOR vulnerability   |
| db (Postgres) | 5433→5432 | Shared database for both app services                    |
| redis         | 6379  | Rate-limit counter store + login lockout tracking           |
| mailpit       | 1025 / 8025 | Local SMTP sink for MFA codes and reset emails         |
| elasticsearch | 9200  | Log storage / search                                        |
| logstash      | —     | Parses log files, ships structured events into Elasticsearch |
| kibana        | 5601  | Analyst dashboards for triage and incident response         |

The web portal runs on **port 4325**, a non-standard port chosen per the brief so
the service is not trivially discoverable and must be found by scanning. The
internal API is deliberately deployed as a **second service on its own port**, so
that a thorough scan surfaces it as an additional attack surface.

### 2.2 Request / detection flow

```
Red Team packet
   -> web (or internal-api) logs the request
   -> if it touches the honeypot or trips a detection, an alert fires
   -> Logstash ships the log line into Elasticsearch
   -> Kibana surfaces it
   -> analyst correlates the attacker's actions into one confirmed incident
   -> incident-response report
```

### 2.3 Application structure

The Flask app is organised into blueprints and handler modules:

- `app.py` — app factory, route wiring, logging config, rate-limit setup
- `auth.py` — registration, login, MFA verification, logout
- `mfa.py` — TOTP blueprint (`/authenticator`, `/api/current-code`)
- `reset.py` — password-reset request + completion
- `honeypot.py` — robots.txt bait and `/backup_secrets/` trap
- `detections.py` — structured Blue-side detection events (TOTP replay)
- `crypto_utils.py` — bcrypt password hashing, Fernet secret encryption
- `models.py` — SQLAlchemy models (User, TOTPSeed, PasswordResetToken, ActivityLog)
- `decorators.py` — `@login_required`,`@admin_required`

## 3. Design decisions

### 3.1 Two-factor authentication model

TOTP protects DriftLock's own login: one issuer, one secret per user, a strict
1:1 relationship. It is a **login second factor**, not a multi-service
authenticator vault. Login is a two-step flow — password first, then the current
six-digit TOTP code — so a stolen password alone is insufficient.

### 3.2 Secret handling

- Passwords are hashed with **bcrypt** (per-password salt via `bcrypt.gensalt()`).
- TOTP seeds are encrypted at rest with **Fernet**, keyed by `MASTER_KEY`. Seeds
  are only decrypted transiently when a code must be generated or verified.
- The `MASTER_KEY` and Flask `SECRET_KEY` are injected via environment variables
  and are gitignored; they are never committed.

### 3.3 Configuration management

All secrets and connection strings come from environment variables (`.env`,
gitignored), consumed through `docker-compose.yml`. The database URL is built
from components so that special characters in the password cannot break URL
parsing.

## 4. Security controls (summary)

Detailed in the Hardening Report; listed here for design context.

- bcrypt password hashing
- Fernet-encrypted TOTP seeds
- Registration input validation (username / email format, password length,
  confirmation match)
- Rate limiting via Flask-Limiter, backed by Redis
- Per-account login lockout after repeated failures (Redis counter, TTL)
- Two-step authentication (password → TOTP)
- Username-enumeration resistance (dummy hash timing, generic error copy)
- Session-fixation resistance (`session.clear()` on privilege change)
- Session-based authorization on sensitive endpoints
- Full request logging + honeypot + ELK detection pipeline

## 5. Intentional vulnerabilities (rationale)

Three planted vulnerabilities, chosen to span difficulty levels and OWASP
categories, and each paired with a matching detection so the Blue Team can prove
it caught the attack.

| # | Difficulty | Class                     | Location                                   |
|---|------------|---------------------------|--------------------------------------------|
| 1 | Easy       | Information disclosure     | `GET /api/debug` (web, 4325)               |
| 2 | Medium     | Broken auth / token replay | MFA verification flow (web, 4325)          |
| 3 | Hard       | Broken access control (IDOR) | `GET /api/v1/users/<id>/setup-status` (5000) |

**Why these three.** The easy one rewards basic port-scan-and-enumerate
methodology and is realistic (debug endpoints left on in development). The medium
one teaches that a *possession* factor is only as strong as its single-use
enforcement — a subtle logic flaw rather than an obvious open door. The hard one
requires discovering a second service and reasoning about authorization, and is
the canonical broken-access-control pattern. Each maps to a detection signal
(`WARNING` on debug access, `mfa_replay_suspected`, `idor_enumeration_suspected`)
so discovery is observable from the defender's side.

Full technical disclosure, exposure, and production fixes are in the project
README and referenced again in the Incident Response Report.

## 6. Wireshark findings (Phase 1 — Observe Before You Build)

> Populate this section from your own capture. The prompts below map to the
> questions in the project brief; attach at least one annotated screenshot
> comparing scan traffic to legitimate traffic, and reference the `.pcap` in
> `logs/captures/`.

- **Network discovery protocol:** _(ARP / ICMP — describe the pattern observed
  for `ping <blue-server-ip>`.)_
- **Open port (TCP handshake):** _(SYN → SYN/ACK → ACK; note the completed
  three-way handshake to port 4325.)_
- **Closed port:** _(SYN → RST/ACK; contrast with the open-port case.)_
- **Recognisable scan pattern:** _(rapid sequential/parallel SYNs across many
  ports from one source in a short window.)_
- **Defensive indicators:** _(burst of connection attempts across a port range,
  many 404s in `access.log`, unusual user-agents such as an Nmap engine string,
  hits on `/backup_secrets/` from the honeypot.)_

Capture file: `logs/captures/<your-capture>.pcap`

## 7. References

- Project brief — Red vs. Blue CTF
- OWASP Top 10 — A01 Broken Access Control, A07 Identification & Authentication Failures
- README — full vulnerability disclosure
