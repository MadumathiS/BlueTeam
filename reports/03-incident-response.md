# 03 — Incident Response Report

**Project:** DriftLock — Blue Team MFA Portal
**Branch:** `patched` (remediated build)
**Engagement period:** July 24 – July 31, 2026
**Systems:** web app (port 4325), internal-api (port 5000)
**Classification:** Lab exercise — Red vs Blue CTF
**Evidence:** `reports/evidence/evidence-snapshot-20260731/`
SHA-256 integrity verified — see `snapshot-manifest.txt`

---

## 1. Executive summary

This report documents the attack activity observed during the engagement and the
remediation applied on this branch. All three intentional vulnerabilities were
exploited on the `main` (vulnerable) build and detected by the Blue Team's
monitoring stack. Every finding is now remediated and verified on this branch.

The attack progressed in four waves across July 24–31:
- **July 24** — honeypot discovery; first attacker contact.
- **July 28** — automated ZAP scanning; IDOR enumeration (8 user IDs, 11
  CRITICAL alerts); honeypot scanner wave.
- **July 30** — debug-endpoint probing (11 hits); credential attacks; first
  Host Header Injection (flag captured).
- **July 31** — sustained Host Header Injection (30+ attempts); honeypot
  activity; automated credential stuffing.

All three vulnerabilities were detected by the ELK pipeline in real time. All
three are closed on this branch, with fixes verified by direct request. The
detection stack remains active on `patched` so attempted attacks are still
visible in Kibana — an attacker probing the patched build sees blocked attempts
logged rather than successful exploitation.

---

## 2. Attack evidence (from `main` build logs)

The following is a summary of what the detection logs recorded during the
engagement. Full detail is in the `main`-branch incident-response report.

### Vulnerability 1 — IDOR (EASY) — detected and remediated

**What happened:** the attacker discovered the internal-api service (port 5000)
via port scan, then enumerated user IDs 1–8 without authorization. A single
source read 8 distinct IDs in one session, triggering 11 CRITICAL
`idor_enumeration_suspected` alerts. User records exposed: `admin`, `Madu`,
and six others. Flag `DRIFTLOCK{1d0r_1nt3rnal_ap1_3xp0s3d}` captured.

**Detection evidence:**
```
{"timestamp":"2026-07-28T08:38:39...","event":"idor_enumeration_suspected",
 "source_ip":"172.18.0.1","requested_id":8,"distinct_ids_seen":3,"severity":"CRITICAL"}
...escalating to distinct_ids_seen=8 across 9 consecutive CRITICAL events
```

### Vulnerability 2 — Information disclosure (MEDIUM) — detected and remediated

**What happened:** the attacker discovered `/api/debug` via path enumeration and
accessed it 11 times across July 30–31. The endpoint returned `python_version`,
`platform`, `flask_env: development`, `app_secret_hint: "check .env file"`, and
the flag. Two source IPs accessed it: `172.18.0.1` (7 hits) and `192.168.20.1`
(4 hits).

**Detection evidence:**
```
2026-07-30 08:10:22,866 | WARNING | 172.18.0.1 | GET /api/debug |
  Debug endpoint accessed by 172.18.0.1
...10 further WARNING events across Jul 30–31
```

### Vulnerability 3 — Host Header Injection (HARD) — detected and remediated

**What happened:** the attacker injected attacker-controlled domains into the
`Host` header of `POST /api/reset-password`, poisoning the emailed reset link
to point at their domain. 30+ injection attempts across July 30–31 using six
distinct injected hosts. Flag `DRIFTLOCK{h0st_h34d3r_1nj3ct10n}` captured.
The most operationally significant injection was `192.168.20.12:4325` —
redirecting the victim's reset link to the attacker's own LAN machine.

**Detection evidence:**
```
2026-07-30 13:26:18,960 | WARNING | 172.18.0.1 | POST /api/reset-password |
  HOST_HEADER_ANOMALY | incoming_host=evil-attacker.com |
  flag=DRIFTLOCK{h0st_h34d3r_1nj3ct10n} | expected_host=localhost:4325
...30+ further HOST_HEADER_ANOMALY events across Jul 30–31
```

### Additional: honeypot (30+ CRITICAL alerts across all four days)

The honeypot fired throughout the engagement. The July 28 wave from
`192.168.20.1` via Chrome produced 20+ CRITICAL hits including OWASP ZAP
fingerprint paths (`zap9158356200558731382`, `.zap5329292479478943320`),
confirming automated scanning. The July 24 and July 31 waves showed the
Firefox-then-curl discovery pattern.

### Additional: credential attacks (not a documented vulnerability)

30+ MFA verify failures against `torvallds` (Jul 30 09:55–11:58), username
enumeration, login failures for `admin`, and 13 rapid-fire credential-stuffing
attempts for `test@gmail.com` in under one second (Jul 31 19:54). Detected by
application WARNING logging.

---

## 3. Remediation applied and verified

### 3.1 — Vulnerability 1: IDOR

**Fix:** the `/api/v1/users/<id>/setup-status` endpoint now requires a valid
`X-Internal-Api-Key` header and rejects unauthorized callers with 403.

**Verification:**
```
$ curl -i http://localhost:5000/api/v1/users/3/setup-status
HTTP/1.1 403 FORBIDDEN
{"error":"Forbidden"}

$ curl -H "X-Internal-Api-Key: <key>" \
       http://localhost:5000/api/v1/users/3/setup-status
HTTP/1.1 200 OK
{"created_at":"2026-07-27T13:12:07...","mfa_enabled":true,
 "user_id":3,"username":"mast"}
```

Anonymous enumeration is blocked. No flag is exposed. Only authorized callers
with the shared secret can read data. A full production fix would additionally
enforce `requested_id == caller_id` so even authorized callers cannot read other
users' records.

### 3.2 — Vulnerability 2: Information disclosure

**Fix:** the `/api/debug` endpoint was removed entirely. Flask `debug=False`.

**Verification:**
```
$ curl -i http://localhost:4325/api/debug
HTTP/1.1 404 NOT FOUND
{"error":"Not found"}
```

No system information is disclosed. The endpoint does not exist.

### 3.3 — Vulnerability 3: Host Header Injection

**Fix:** the emailed reset link is now built from the configured trusted base URL
(`APP_URL` environment variable) rather than the incoming `Host` header. A
spoofed `Host` header is inspected and logged as `HOST_HEADER_ANOMALY` but never
used to construct the link.

**Verification (link not poisoned):**
```
$ curl -X POST http://localhost:4325/api/reset-password \
       -H "Host: evil-attacker.com" \
       -H "Content-Type: application/json" \
       -d '{"email": "mast@driftlock.com"}'
{"message":"If an account with that email exists, a reset link has been sent."}
```

Emailed reset link (verified in Mailpit):
```
http://localhost:4325/reset-password/QbtKLKi3E0JRgAd5NqpLQS-3u2Fbm6a7biOgtE0dvWk
```

The link points at `localhost:4325` (the trusted `APP_URL`), not
`evil-attacker.com`. The attack is neutralized.

**Detection still active on patched (defense-in-depth):**
```
$ docker compose exec web grep "HOST_HEADER_ANOMALY" /app/logs/detections.log
{"timestamp":"2026-07-30T23:46:33...","event":"HOST_HEADER_ANOMALY",
 "incoming_host":"evil-attacker.com","expected_host":"localhost:4325",
 "source_ip":"172.18.0.1","path":"/reset-password",
 "note":"blocked_link_built_from_APP_URL","severity":"HIGH"}
```

The attempt is detected and logged with `note: blocked_link_built_from_APP_URL`
confirming the fix held. No flag is emitted on `patched`.

### 3.4 — Additional finding: hardcoded token in `/api/profile`

Identified by the Red Team via source review. Not one of the three intentional
vulnerabilities.

**Fix:** the hardcoded bearer token was removed; the endpoint authenticates via
session only.

**Verification:**
```
$ curl -i -H "Authorization: Bearer valid-session-token-123" \
       http://localhost:4325/api/profile
HTTP/1.1 302 FOUND   (redirect to /login — old token no longer works)
```

### 3.5 — Supporting hardening

- `MASTER_KEY` now fails closed if unset (was silently regenerating a throwaway
  key, which would render stored TOTP seeds undecryptable on restart).
- `debug=False` enforced; Werkzeug debugger not exposed.

---

## 4. Detection coverage — patched build

The detection stack remains fully active on `patched`. Any future exploitation
attempt is still captured and visible in Kibana:

| Detection | Signal | Index |
|---|---|---|
| IDOR enumeration | `idor_enumeration_suspected` CRITICAL | `driftlock-internal-api-*` |
| Debug access | `WARNING GET /api/debug` | `driftlock-access-*` |
| Host Header Injection | `HOST_HEADER_ANOMALY` JSON (with `note: blocked`) | `driftlock-detections-*` |
| Honeypot | `honeypot_hit` CRITICAL | `driftlock-honeypot-*` |
| Credential attacks | `WARNING POST /api/login`, `POST /verify-mfa` | `driftlock-access-*` |

On `patched`, a Host Header Injection attempt is detected and logged as
`blocked_link_built_from_APP_URL` — the detection fires but the attack fails.
This provides ongoing visibility even after remediation.

---

## 5. Production recommendations

Beyond the applied fixes, a production deployment should:

- Add per-user identity binding on the internal API (`requested_id == caller_id`)
  in addition to the shared-secret control.
- Prefer unguessable identifiers (UUIDs) over sequential integer IDs.
- Validate the `Host` header against an allowlist (`EXPECTED_HOST`) in addition
  to the trusted-base-URL construction.
- Verify account lockout engaged during the Jul 30 MFA brute-force (30+ failures
  against `torvallds`); if not, adjust the lockout threshold.
- Run behind a production WSGI server; enable HTTPS; move secrets to a secret
  manager; enable ELK authentication.

---

## 6. Conclusion

All three documented vulnerabilities were exploited during the engagement,
detected by the Blue Team's monitoring stack, and are now remediated on this
branch. Every fix has been verified by direct request. The detection stack
continues to run on `patched`, providing ongoing monitoring and logging of any
future attempts — including the ability to show "attempt detected but blocked"
for Host Header Injection.

The complete evidence chain — log snapshot with SHA-256 checksums, verification
commands and outputs, and this report — is committed to `reports/evidence/` and
`reports/`. The detection-to-remediation cycle is documented end to end.