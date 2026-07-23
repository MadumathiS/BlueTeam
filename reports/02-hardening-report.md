# 02 — Hardening Report

**Project:** DriftLock — Blue Team MFA Portal
**Focus:** Security controls, why each was chosen, and the defense-in-depth strategy

---

## 1. Purpose

This report documents the genuine security controls implemented in DriftLock —
everything that is meant to be secure, as opposed to the three deliberately
planted vulnerabilities. The intent is a target that resists casual attack, so
the planted weaknesses must be found by real reconnaissance.

## 2. Security controls

### 2.1 Password storage — bcrypt

Passwords are hashed with bcrypt using a per-password salt (`bcrypt.gensalt()`)
in `crypto_utils.py`. Plaintext passwords are never stored or logged.

**Why:** bcrypt is an adaptive, salted hash designed to resist brute force and
rainbow-table attacks. A per-password salt defeats precomputation and means
identical passwords produce different hashes.

### 2.2 TOTP seed encryption — Fernet

Each user's TOTP secret is encrypted at rest with Fernet (`encrypt_secret` /
`decrypt_secret`), keyed by `MASTER_KEY`. Seeds are decrypted only transiently
when a code is generated or verified.

**Why:** the TOTP seed is the long-lived root of the second factor. If the
database were exfiltrated, encrypted seeds are useless without the separately-held
`MASTER_KEY`, so a DB leak alone does not compromise MFA.

### 2.3 Input validation

Registration validates username format (`^[a-zA-Z0-9_]{3,20}$`), email format,
minimum password length (8), and password/confirmation match, server-side in
`auth.py`. Client-side attributes (`minlength`, `pattern`) exist for UX but are
never relied on for security.

**Why:** server-side validation is the authoritative boundary; client controls
can be bypassed. Strict character sets reduce injection and abuse surface.

### 2.4 Rate limiting — Flask-Limiter + Redis

Global default limit of 100/minute, with tighter per-route limits: registration
5/min, login 3/min, MFA verify 5/min, profile 10/min. Counters are stored in
Redis so limits are consistent and survive restarts.

**Why:** rate limiting throttles brute-force and credential-stuffing attempts and
blunts rapid endpoint enumeration. Redis-backed storage keeps counters correct
rather than per-process in-memory.

### 2.5 Account lockout

After `MAX_LOGIN_ATTEMPTS` (3) failures for a given username, further attempts
are refused for `LOCKOUT_SECONDS` (60), tracked with a Redis counter and TTL in
`auth.py`. The login UI surfaces remaining-attempt counts and a lockout state.

**Why:** complements rate limiting by binding failures to the targeted account,
not just the source IP, making online password guessing impractical.

### 2.6 Two-step authentication

Login verifies the password, and only then — for MFA-enabled accounts — requires
the current TOTP code before establishing an authenticated session. The password
step sets a `pending_mfa_user_id`; the session is not privileged until TOTP
succeeds.

**Why:** defense in depth for authentication. A stolen or guessed password does
not by itself grant access.

### 2.7 Username-enumeration resistance

When a username does not exist, login still performs a bcrypt verification
against a constant `DUMMY_HASH`, and error messages are generic ("Invalid
username or password").

**Why:** without the dummy verification, a missing user would return
noticeably faster, letting an attacker enumerate valid usernames by timing.
Constant work + generic errors removes that oracle.

### 2.8 Session-fixation resistance

On any privilege transition — successful password step, MFA success, login —
the session is cleared (`session.clear()`) before new authenticated values are
set.

**Why:** prevents an attacker who fixed a victim's pre-auth session identifier
from riding it into an authenticated session.

### 2.9 Authorization on sensitive endpoints

The `@login_required` and `@admin_required` decorators gate authenticated views
and return 401 (JSON) or redirect to login (HTML). The TOTP dashboard and
current-code endpoints are protected, and the current-code endpoint is scoped to
the session user. `@admin_required` further restricts the admin dashboard to
accounts flagged as administrators; regular users are confined to their own
activity view.

**Why:** sensitive functionality must verify an authenticated session rather than
trusting client state.

### 2.10 Secure password reset

Reset tokens are random (`secrets.token_urlsafe(32)`), stored only as SHA-256
hashes, single-use, and expire after 15 minutes. Requests return an
enumeration-safe response regardless of whether the email exists. Prior unused
tokens for a user are invalidated when a new one is issued.

**Why:** hashed-at-rest tokens mean a DB read cannot reset passwords; expiry and
single-use bound the window; the uniform response prevents account enumeration
via the reset flow.

### 2.11 Logging and monitoring

Every request is logged to `access.log` with timestamp, level, source IP, method,
and path. Honeypot hits, TOTP-replay detections, and internal-api events are
written as structured JSON. Logstash parses all of these into Elasticsearch under
dedicated indices for Kibana triage.

**Why:** detection and incident response depend on complete, structured,
searchable logs. Separating high-signal alerts into their own indices keeps
triage fast.

### 2.12 Network segmentation and port exposure

Only the services that must be publicly reachable are bound to all interfaces.
Internal services — PostgreSQL, Redis, Elasticsearch, and the SMTP listener —
are bound to `127.0.0.1` only, so they are unreachable from the external network
even though the containers are running. Docker Compose defines separate
`frontend` and `backend` networks, with the backend marked `internal: true` so
containers attached to it have no route off the host.

**Why:** a port scan from the lab network should surface only the intended attack
surface. Binding datastores to loopback means a scanner never sees Postgres,
Redis, or Elasticsearch, and even a compromised container on the backend network
cannot reach outward. This is what makes the deliberately-exposed `internal-api`
a *chosen* attack surface rather than one of many.

### 2.13 Host firewall (UFW)

The host firewall is active with a default-deny inbound policy, permitting only
SSH (22) and the three intentionally-public services: the DriftLock portal
(4325), MailHog (8025), and Kibana (5601).

**Why:** defence in depth behind the Docker port bindings — even if a container
were misconfigured to publish a port, the host firewall still refuses the
connection. Default-deny means new services are closed until explicitly opened.

### 2.14 Container hardening

Each application container is constrained at runtime:

- **Non-root execution** — the web image creates and switches to an unprivileged
  `appuser`; the process does not run as root.
- **`no-new-privileges:true`** — prevents a process inside the container from
  gaining additional privileges via setuid binaries.
- **`cap_drop: ALL`** — all Linux capabilities are dropped, so the container
  cannot perform privileged kernel operations.
- **Secrets via environment variables** — credentials and keys are injected at
  runtime, never baked into image layers.

**Why:** these limit the blast radius of a successful application compromise. An
attacker who achieves code execution lands as an unprivileged user, in a
capability-stripped container, unable to escalate — turning what could be host
compromise into a contained incident.

## 3. Defense-in-depth summary

Authentication is protected by overlapping layers rather than any single control:

```
Password guessing must survive:
   rate limiting (3/min)  +  per-account lockout (3 fails / 60s)
   +  bcrypt cost         +  enumeration-resistant errors

Account takeover must additionally survive:
   TOTP second factor     +  session-fixation resets

Data-at-rest exposure is mitigated by:
   bcrypt password hashes +  Fernet-encrypted TOTP seeds
   +  hashed, expiring, single-use reset tokens

Everything is observed by:
   full request logging   +  honeypot  +  structured detections  +  ELK

The infrastructure beneath it is constrained by:
   loopback-bound datastores  +  internal backend network
   +  UFW default-deny         +  non-root containers
   +  no-new-privileges        +  cap_drop ALL
```

No single failure collapses the system: bypassing one layer still leaves the
others standing, and any probing generates observable log signal. Even a
successful application compromise lands in an unprivileged, capability-stripped
container with no route to the internal datastores.

## 4. Verification tests

The infrastructure controls in 2.12–2.14 were verified on the deployed stack.
Each test below was executed against the running environment; evidence
screenshots are held in the project's security-check document.

### Test 1 — Port binding

Internal services were probed on the host's external IP and confirmed
unreachable, while the intended public services responded normally.

| Service | Port | Expected | Result |
|---------|------|----------|--------|
| PostgreSQL | 5433 | BLOCKED | BLOCKED — correct |
| Redis | 6379 | BLOCKED | BLOCKED — correct |
| Elasticsearch | 9200 | BLOCKED | BLOCKED — correct |
| SMTP (MailHog) | 1025 | BLOCKED | BLOCKED — correct |
| DriftLock portal | 4325 | REACHABLE | REACHABLE — correct |
| MailHog UI | 8025 | REACHABLE | REACHABLE — correct |
| Kibana | 5601 | REACHABLE | REACHABLE — correct |

Internal services are bound to `127.0.0.1` only and are therefore invisible to a
scan from the lab network.

### Test 2 — Host firewall active

`ufw status` reports **Status: active** with a default-deny inbound policy and
allow rules for only 22, 4325, 8025, and 5601 (IPv4 and IPv6).

### Test 3 — Docker networks exist

Both `frontend` and `backend` bridge networks are present in `docker network ls`.

### Test 4 — Backend network is internal

Inspecting the backend network confirms `"Internal": true`, so containers on it
have no external route.

### Test 5 — Containers run as non-root

`whoami` inside the web container returns **appuser**, not root.

### Test 6 — no-new-privileges is set

Container inspection confirms the `no-new-privileges:true` security option is
applied.

### Test 7 — cap_drop is applied

Container inspection confirms `CapDrop: [ALL]` — all Linux capabilities dropped.

**Result:** all seven checks passed, confirming the network, firewall, and
container-runtime controls are in force on the deployed stack.

## 5. Known / accepted items

- **`debug=True` in `app.py`** exposes the Werkzeug debugger (potential RCE) and
  is **not** one of the three intentional vulnerabilities. It must be set to
  `debug=False` for any graded or demo run to avoid an accidental weakness
  beyond the planted ones. *(Tracked in README "Remaining".)*
- **`MASTER_KEY` fallback** should fail closed rather than auto-generating a
  throwaway key, since a regenerated key makes previously-encrypted TOTP seeds
  permanently undecryptable. *(Tracked in README "Remaining".)*
- The three intentional vulnerabilities are documented weaknesses and are
  deliberately **not** hardened.

## 6. References

- Project brief — Blue Team hardening requirements
- OWASP Top 10 — A02 Cryptographic Failures, A07 Identification & Authentication Failures
- `crypto_utils.py`, `auth.py`, `reset.py`, `app.py`, `decorators.py`, `docker-compose.yml`, `web/Dockerfile`
- Security check evidence — `Security_check_DriftLock.docx` (7 verification tests)