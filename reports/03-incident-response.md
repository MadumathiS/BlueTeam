# 03 — Incident Response Report

**Project:** DriftLock — Blue Team MFA Portal
**Branch:** `main` (intentionally-vulnerable CTF target)
**Date of incident:** July 24, 2026
**System:** web app (port 4325), internal-api (port 5000)
**Classification:** Lab exercise — Red vs Blue CTF

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

Follow-on activity (July 26) showed repeated `GET /api/debug` requests and further
`/api/v1/users/<id>/setup-status` enumeration.

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
`/api/v1/users/1/setup-status` and `/users/2/setup-status` directly.

**Information disclosure.** Repeated `GET /api/debug` requests (logged at WARNING)
show the attacker located and repeatedly queried the unauthenticated debug
endpoint.

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
- **Application WARNING events** — `/api/debug` access and failed MFA attempts are
  logged at WARNING.
- **Independent service logs** — the internal-api service logged the Nmap probe,
  corroborating a multi-port scan.
- **Centralized triage (ELK)** — all logs ship to Elasticsearch; Kibana allows
  correlating one source across the honeypot, access, and internal-api indices.

**Triage lesson.** The honeypot hit is unambiguous signal; the scan burst is signal
by pattern; ordinary favicon/registration traffic is benign noise. Correlating a
single source across multiple detections is what elevates an event from
"suspicious" to "confirmed incident."

---

## 7. Recommended fixes (production)

These vulnerabilities are intentional CTF targets on this branch. In a real
deployment they would be remediated as follows (and are, on the `patched` branch):

**Vulnerability 1 — `/api/debug`.** Remove the endpoint or gate it behind
authentication and restrict to internal networks; disable Flask debug mode.

**Vulnerability 2 — TOTP replay.** Record each consumed code/counter per user and
reject reuse within the validity window.

**Vulnerability 3 — IDOR.** Enforce authorization: verify the requested id matches
the caller's identity (or an admin role); prefer unguessable identifiers; do not
expose internal APIs to untrusted networks.

**Additional finding — `/api/profile`.** Remove hardcoded credentials from source;
authenticate via session or an environment-supplied secret.

**Cross-cutting.** Production WSGI server, HTTPS, secrets via a secret manager, and
authentication on the ELK stack.

---

## 8. Conclusion

The exercise demonstrated a complete detect-and-analyze cycle: reconnaissance,
honeypot triggering, IDOR enumeration, and debug-endpoint access were all captured
and attributed through layered logging, with the honeypot providing the earliest
high-confidence alert. Remediation of all findings is demonstrated on the `patched`
branch.