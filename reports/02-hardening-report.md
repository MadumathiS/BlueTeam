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

The `@login_required` and `@admin_required` decorators protect authenticated
views by enforcing session-based authentication and authorization checks. They
return a 401 response (JSON) for unauthenticated API requests or redirect
unauthenticated browser users to the login page (HTML). The TOTP dashboard and
current-code endpoints are protected, and the current-code endpoint is scoped
to the authenticated session user.

**Why:** Sensitive functionality must validate server-side authentication and
authorization rather than trusting client-side state or user-controlled data.

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

### 2.12 Deployment hardening

The web container builds its dependencies then drops to a non-root `appuser`.
Secrets are injected via environment variables, never baked into images. Services
are isolated via Docker Compose networking.

**Why:** running as non-root limits blast radius if the app process is
compromised; env-injected secrets keep credentials out of the image layers.

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
```

No single failure collapses the system: bypassing one layer still leaves the
others standing, and any probing generates observable log signal.

## 4. Known / accepted items

- **`debug=True` in `app.py`** exposes the Werkzeug debugger (potential RCE) and
  is **not** one of the three intentional vulnerabilities. It must be set to
  `debug=False` for any graded or demo run to avoid an accidental weakness
  beyond the planted ones. *(Tracked in README "Remaining".)*
- **`MASTER_KEY` fallback** should fail closed rather than auto-generating a
  throwaway key, since a regenerated key makes previously-encrypted TOTP seeds
  permanently undecryptable. *(Tracked in README "Remaining".)*
- The three intentional vulnerabilities are documented weaknesses and are
  deliberately **not** hardened.

## 5. References

- Project brief — Blue Team hardening requirements
- OWASP Top 10 — A02 Cryptographic Failures, A07 Identification & Authentication Failures
- `crypto_utils.py`, `auth.py`, `reset.py`, `app.py`, `docker-compose.yml`
