# 03 — Incident Response Report

**Project:** DriftLock — Blue Team MFA Portal
**Branch:** `patched` (remediated build)
**Date of incident:** July 24, 2026
**System:** web app (port 4325), internal-api (port 5000)
**Classification:** Lab exercise — Red vs Blue CTF

> **Note:** The incident timeline and exploitation evidence below reflect the
> activity observed to date. Sections 3–5 will be reconciled with the Red Team's
> final report once received; in particular, Host Header Injection exploitation
> evidence (`HOST_HEADER_ANOMALY` events on the `/api/reset-password` endpoint)
> will be added to the timeline and log analysis when their report confirms the
> requests they issued.

---

## 1. Executive summary

On July 24, 2026, the DriftLock portal was subjected to reconnaissance and
exploitation activity consistent with a Red Team engagement. The activity followed
a recognizable chain: automated port/path scanning, discovery of `robots.txt`,
triggering of the honeypot decoy, and enumeration of the IDOR endpoint, with
repeated access to the debug endpoint. Every stage was detected through layered
logging; the honeypot produced three CRITICAL alerts automatically. No production
data was exposed — the only "sensitive" material reached was the intentional decoy.

---

## 2. Attribution note

Most malicious requests on July 24 originated from `172.18.0.1`, the Docker bridge
gateway (host-originated traffic reaching the container), with additional requests
from `192.168.20.12` (the lab VM's LAN address). "The attacker" below refers to the
source(s) generating this activity, regardless of network path.

---

## 3. Incident timeline (July 24, 2026)

| Time (UTC) | Source | Action | Stage / Target | Detected by |
|---|---|---|---|---|
| 14:07–14:08 | 192.168.20.12 | GET `/eartlogo.png`, `/robot.txt` | Early probing | access.log |
| 14:21:12 | 192.168.20.12 | GET `/nice ports,/Trinity.txt.bak` (internal-api) | Nmap probe | internal-api.log |
| 14:57:09 | 172.18.0.1 | ~15 paths in one second (`/.git/HEAD`, `/nmaplowercheck…`, `/HNAP1`, …) | Automated scan | access.log |
| 14:58 | 172.18.0.1 | `/roboxtt.t`, `/robot.txt` variants | robots.txt discovery | access.log |
| 14:59:07 | 172.18.0.1 | GET `/backup_secrets/` (Firefox UA) | Honeypot bait (manual) | honeypot.log — CRITICAL |
| 15:01:26 | 172.18.0.1 | GET `/backup_secrets/db_backup_2024.sql.bak` (curl) | Decoy exfil (scripted) | honeypot.log — CRITICAL |
| 15:02:17 | 172.18.0.1 | Same decoy re-download (curl) | Honeypot re-hit | honeypot.log — CRITICAL |
| 15:03:26–15:03:49 | 172.18.0.1 | `/api/v1/users/1`, `/api/v1/ocean/1`, `/api/v1/admin/1` | IDOR enumeration | access.log |
| 15:20:05 | 192.168.20.12 | GET `/nice ports,/Trinity.txt.bak` | Nmap signature | access.log |

Follow-on activity (July 26 onward) showed repeated `GET /api/debug` requests and
further `/api/v1/users/<id>/setup-status` enumeration. Host Header Injection
activity against `/api/reset-password` (`HOST_HEADER_ANOMALY`) will be added here
once confirmed against the Red Team's report.

---

## 4. Evidence of reconnaissance

The clearest signature is the burst at **14:57:09**: over a dozen distinct paths
requested within one second from a single source, including
`/nmaplowercheck1784905029`, `/HNAP1`, `/.git/HEAD`, and `/evox/about` —
characteristic of automated scanner wordlists. No human browses fifteen unrelated
administrative paths in one second.

Independent corroboration appears in the **internal-api log**: a request to
`/nice ports,/Trinity.txt.bak` — a known Nmap service-detection artifact — from
`192.168.20.12`. Because this hit a separate service (port 5000), it confirms the
scan swept multiple ports.

**Wireshark evidence.** Scan and legitimate traffic were captured on the lab host
(single-host setup; loopback interface), retained in `logs/captures/`:
`scan_lo.pcap` (a port scan — a single source issuing SYN packets to hundreds of
ports within milliseconds, and on open ports completing the handshake then
immediately sending RST with no data) and `legit.pcap` (a normal session — full
handshake, real HTTP GET, server response with data, graceful FIN close).
Annotated screenshots are included: `wireshark-scan-portsweep.png`,
`wireshark-openport-detection.png`, `wireshark-legitimate-traffic.png`.

---

## 5. Log analysis: exploitation attempts

**Honeypot (highest confidence).** Three CRITICAL alerts. A notable behavioral
detail: the first `/backup_secrets/` hit used a Firefox user-agent (manual
discovery), while the decoy-file downloads used curl (scripted) — a
discovery-then-automation progression. The exfiltrated file is the intentional
decoy; no real data was exposed.

**IDOR enumeration.** The attacker requested `/api/v1/users/1`, then varied the
path and ID (`/api/v1/ocean/1`, `/api/v1/admin/1`), then hit
`/api/v1/users/1/setup-status` and `/users/2/setup-status` directly. When a single
source read three or more distinct IDs, the internal-api detection escalated to a
CRITICAL `idor_enumeration_suspected` alert.

**Information disclosure.** Repeated `GET /api/debug` requests (logged at WARNING)
show the attacker located and repeatedly queried the unauthenticated debug
endpoint.

**Host Header Injection.** *(Pending Red Team report.)* Attempts to poison the
password-reset link via a spoofed `Host` header on `POST /api/reset-password` are
recorded as `HOST_HEADER_ANOMALY` events with the incoming host value and source
IP. This section will be populated with the observed requests once reconciled with
the Red Team's report.

**Additional finding.** The Red Team also identified, via source review, a
hardcoded bearer token in `/api/profile` (`valid-session-token-123`). This was not
one of the three intentional vulnerabilities and is treated as an additional
finding.

---

## 6. How the attack was detected

- **Honeypot alerts** — any `/backup_secrets/` request is inherently hostile;
  three CRITICAL alerts fired automatically with source IP, user-agent, and time.
- **Access-log pattern analysis** — the one-second scanner burst is a recognizable
  reconnaissance signature, distinct from human-paced browsing.
- **Application WARNING events** — `/api/debug` access and Host-header anomalies on
  `/api/reset-password` are logged at WARNING.
- **Independent service logs** — the internal-api service logged the Nmap probe and
  the IDOR enumeration, corroborating a multi-port scan and flagging enumeration.
- **Centralized triage (ELK)** — all logs ship to Elasticsearch; Kibana allows
  correlating one source across the honeypot, access, and internal-api indices.

**Triage lesson.** The honeypot hit is unambiguous signal; the scan burst is signal
by pattern; ordinary favicon/registration traffic is benign noise. Correlating a
single source across multiple detections is what elevates an event from
"suspicious" to "confirmed incident."

---

## 7. Remediation applied and verified

Unlike the vulnerable (`main`) build, this `patched` branch has the vulnerabilities
remediated. Each fix and its verification is below.

### 7.1 Vulnerability 1 — IDOR `/api/v1/users/<id>/setup-status`
**Fix:** the endpoint now requires a valid `X-Internal-Api-Key` header and rejects
unauthorized callers with 403, blocking anonymous enumeration.
**Verification:**
```
$ curl -i http://localhost:5000/api/v1/users/3/setup-status
HTTP/1.1 403 FORBIDDEN
{"error":"Forbidden"}

$ curl -H "X-Internal-Api-Key: <key>" \
       http://localhost:5000/api/v1/users/3/setup-status
HTTP/1.1 200 OK
{"user_id":3,"username":"mast","mfa_enabled":true,"created_at":"..."}
```
Anonymous enumeration is blocked (403); only a caller presenting the shared secret
can read data. A full production fix would additionally bind each request to the
authenticated user's own identity.

### 7.2 Vulnerability 2 — `/api/debug` (information disclosure)
**Fix:** the endpoint was removed entirely and Flask debug mode disabled
(`debug=False`).
**Verification:**
```
$ curl -i http://localhost:4325/api/debug
HTTP/1.1 404 NOT FOUND
{"error":"Not found"}
```
The endpoint no longer exists; no system information is disclosed.

### 7.3 Vulnerability 3 — Host Header Injection (password-reset poisoning)
**Fix:** the emailed reset link is now built from a configured trusted base URL
(`APP_URL`) instead of the incoming `Host` header, so a spoofed `Host` can no
longer redirect the reset link to an attacker-controlled domain.
**Verification:**
```
$ curl -X POST http://localhost:4325/api/reset-password \
       -H "Host: evil-attacker.com" \
       -H "Content-Type: application/json" \
       -d '{"email": "victim@example.com"}'
```
On `main`, this poisoned the emailed reset link to point at `evil-attacker.com`.
On `patched`, the reset link is built from the trusted `APP_URL`, so the emailed
link points at the legitimate host regardless of the spoofed `Host` header. A full
production fix additionally validates the `Host` header against an allowlist
(`EXPECTED_HOST`) as defense-in-depth.

### 7.4 Additional finding — hardcoded token in `/api/profile`
Identified by the Red Team via source review (not one of the three planted
vulnerabilities).
**Fix:** the hardcoded bearer token was removed; the endpoint now authenticates via
the user's session.
**Verification:**
```
$ curl -i -H "Authorization: Bearer valid-session-token-123" \
       http://localhost:4325/api/profile
HTTP/1.1 302 FOUND        (redirect to /login — old token no longer works)
```

### 7.5 Supporting hardening
- `MASTER_KEY` now fails closed if unset, instead of silently generating a
  throwaway key that would render stored TOTP seeds undecryptable on restart.

### 7.6 Production recommendations (beyond the lab fixes)
- IDOR: add per-user identity binding on top of the shared-secret control; prefer
  unguessable identifiers (UUIDs) over sequential integer IDs.
- Host Header: validate `Host` against an allowlist in addition to the
  trusted-base-URL construction.
- Run behind a production WSGI server; enable HTTPS; move secrets to a secret
  manager; enable authentication on the ELK stack.

---

## 8. Conclusion

This branch demonstrates the full defensive cycle end to end: the Red Team's
reconnaissance, honeypot triggering, and IDOR/debug exploitation were detected and
attributed through layered logging; and every finding — the three intentional
vulnerabilities plus the additional hardcoded-token finding — has been remediated
and verified. The honeypot provided the earliest high-confidence alert; the ELK
pipeline enabled single-source correlation; and the patched build confirms each
exploited weakness is now closed. The incident timeline and exploitation evidence
will be finalized once reconciled with the Red Team's report.