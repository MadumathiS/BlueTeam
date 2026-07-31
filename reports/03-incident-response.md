# 03 — Incident Response Report

**Project:** DriftLock — Blue Team MFA Portal
**Branch:** `main` (intentionally-vulnerable CTF target)
**Engagement period:** July 24 – July 31, 2026
**Systems:** web app (port 4325), internal-api (port 5000)
**Classification:** Lab exercise — Red vs Blue CTF
**Evidence:** `reports/evidence/evidence-snapshot-20260731/`
SHA-256 integrity verified — see `snapshot-manifest.txt`

---

## 1. Executive summary

Between July 24 and July 31, 2026, the DriftLock portal was subjected to
sustained, multi-day reconnaissance and exploitation. The attack progressed in
four distinct waves: honeypot discovery on July 24, automated scanning and IDOR
enumeration on July 28, credential attacks and debug-endpoint probing on July 30,
and sustained Host Header Injection on July 30–31.

All three documented intentional vulnerabilities were exploited and detected:

- **Vulnerability 1 (IDOR):** one source enumerated 8 distinct user IDs,
  triggering 11 CRITICAL `idor_enumeration_suspected` alerts.
- **Vulnerability 2 (Debug endpoint):** 11 accesses across two days from two
  source IPs, each logged at WARNING.
- **Vulnerability 3 (Host Header Injection):** 30+ injection attempts across
  two days using six distinct injected domains; flag captured.

The honeypot produced 30+ CRITICAL alerts across all four incident days including
a ZAP automated-scanner wave on July 28. Significant credential-attack activity
(MFA brute-force, credential stuffing, username enumeration) was also detected by
the application's rate-limiting and warning infrastructure.

No production data was exposed. All "sensitive" material reached was the
intentional decoy (honeypot backup file). Every stage of the attack left a
detectable trail, and all findings are corroborated by log evidence committed to
`reports/evidence/`.

---

## 2. Attribution

Two source IPs account for all activity:

- **`172.18.0.1`** — Docker bridge gateway; traffic from the host reaching the
  container via loopback.
- **`192.168.20.1`** — the attacking machine's LAN address (direct network path).
- **`192.168.20.12`** — appeared once (Jul 31 12:51) as a direct source in a
  Host Header anomaly event, consistent with the same machine on a different
  interface.

Both IPs appear across all three vulnerability detections and the honeypot,
confirming a single attacker operating from one machine via two network paths.

---

## 3. Incident timeline

### Wave 1 — July 24: Honeypot discovery and first contact

| Time (UTC) | Source | Event | Log |
|---|---|---|---|
| 14:59:07 | 172.18.0.1 | GET `/backup_secrets/` — Firefox/Linux UA (manual) | honeypot.log — CRITICAL |
| 15:01:26 | 172.18.0.1 | GET `/backup_secrets/db_backup_2024.sql.bak` — curl (scripted) | honeypot.log — CRITICAL |
| 15:02:17 | 172.18.0.1 | Same decoy file re-downloaded — curl | honeypot.log — CRITICAL |

Three CRITICAL honeypot alerts within 3 minutes. The Firefox-then-curl progression
confirms manual discovery of `robots.txt` followed by immediate scripted
exploitation — the attacker found the decoy path, then automated the download.
This is the earliest confirmed attack activity in the logs.

### Wave 2 — July 28: Automated scanning and IDOR enumeration

| Time (UTC) | Source | Event | Log |
|---|---|---|---|
| 08:37:30 | 172.18.0.1 | GET `/api/v1/users/4/setup_status` — Firefox UA | internal-api.log |
| 08:37:40 | 172.18.0.1 | GET `/api/v1/users/voldamot/setup_status` — username probe | internal-api.log |
| 08:37:49 | 172.18.0.1 | GET `/api/v1/users/7/setup_status` | internal-api.log |
| 08:38:20 | 172.18.0.1 | GET `/api/v1/users/8/setup_status` ×2 | internal-api.log |
| 08:38:39 | 172.18.0.1 | `idor_enumeration_suspected` — distinct_ids_seen=3 | internal-api.log — **CRITICAL** |
| 08:39:00–35 | 172.18.0.1 | IDs 0–6 walked — distinct_ids_seen reaches 8 | internal-api.log — **CRITICAL** ×8 |
| 14:17:07 | 192.168.20.1 | Honeypot: `/backup_secrets/` — Chrome/Windows UA | honeypot.log — **CRITICAL** |
| 14:17:52 | 192.168.20.1 | Honeypot: random numeric paths ×2 | honeypot.log — **CRITICAL** |
| 14:33:46–14:34:39 | 192.168.20.1 | Honeypot: 15+ paths — `.env`, `.git/config`, `.htaccess`, `actuator/health`, ZAP fingerprints, SVN/CVS paths | honeypot.log — **CRITICAL** ×15+ |

The IDOR session starting at 08:37 used a Firefox user-agent for the initial
probes, suggesting manual discovery, before systematically walking IDs 1–8 and
triggering 9 CRITICAL alerts. The afternoon honeypot wave (14:17–14:34) from
`192.168.20.1` via Chrome is a clear automated-scanner signature: the paths
`zap9158356200558731382` and `.zap5329292479478943320` are OWASP ZAP's
fingerprinting probes, alongside common wordlist paths (`trace.axd`, `lfm.php`,
`/backup_secrets/.env`, `/backup_secrets/.git/config`). Sub-second timing across
20+ paths confirms no human was typing these.

### Wave 3 — July 30: Debug endpoint and first Host Header Injection

| Time (UTC) | Source | Event | Log |
|---|---|---|---|
| 08:10–09:44 | 172.18.0.1 / 192.168.20.1 | GET `/api/debug` ×6 | access.log — WARNING |
| 09:55–11:58 | 192.168.20.1 | 30+ MFA verify failures for `torvallds` | access.log — WARNING |
| 10:02–10:03 | 192.168.20.1 | Login failures (no such user) ×4 — username enumeration | access.log — WARNING |
| 10:21, 11:06 | 192.168.20.1 | GET `/api/debug` ×2 | access.log — WARNING |
| 10:27, 11:41 | 192.168.20.1 | Login failures for `admin` | access.log — WARNING |
| 13:26:18 | 172.18.0.1 | HOST_HEADER_ANOMALY `incoming_host=evil-attacker.com` — **flag captured** | access.log — WARNING |
| 14:14:39–15:05 | 192.168.20.1 | HOST_HEADER_ANOMALY ×6 — `incoming_host=192.168.20.12:4325` | access.log — WARNING |

July 30 is when all three documented vulnerabilities were actively exploited.
Debug-endpoint access began at 08:10. The MFA brute-force against `torvallds`
(30+ failures, 09:55–11:58) targeted a valid username with repeated email-code
guesses. The first Host Header injection at 13:26 from `172.18.0.1` with
`evil-attacker.com` is the primary exploit event — the flag was captured in the
emailed reset link. The afternoon injections from `192.168.20.1` using
`192.168.20.12:4325` represent a more operationally realistic variant: pointing
the reset link at the attacker's own LAN address to capture the token locally.

### Wave 4 — July 31: Sustained exploitation

| Time (UTC) | Source | Event | Log |
|---|---|---|---|
| 08:07–08:08 | 192.168.20.1 | Login failures (no such user) ×5 rapid burst | access.log — WARNING |
| 08:15–09:20 | 192.168.20.1 | HOST_HEADER_ANOMALY ×8 — `192.168.20.12:4325` | access.log — WARNING |
| 09:41 | 172.18.0.1 | HOST_HEADER_ANOMALY — `localhost:4326` | access.log — WARNING |
| 10:14 | 172.18.0.1 | HOST_HEADER_ANOMALY — `evil-attacker.com` — **flag** | access.log — WARNING |
| 10:24, 10:37–38 | 192.168.20.1 | HOST_HEADER_ANOMALY ×3 — `evil-attacker.com` — **flag** | access.log — WARNING |
| 12:38:26 | 172.18.0.1 | HOST_HEADER_ANOMALY — `kien.com` — **flag** | access.log — WARNING |
| 12:50–12:53 | 172.18.0.1 | Honeypot: `/backup_secrets/` ×3 — curl | access.log — CRITICAL |
| 12:51:51 | 192.168.20.12 | HOST_HEADER_ANOMALY — `evil-attacker.com` (direct LAN source) | access.log — WARNING |
| 13:04–13:06 | 192.168.20.1 | HOST_HEADER_ANOMALY ×3 — `evil-attacker.com` + `amimean.enough` | access.log — WARNING |
| 13:04:20 | 192.168.20.1 | Honeypot: `/backup_secrets/` — curl/8.18.0 | access.log — CRITICAL |
| 13:07:06 | 192.168.20.1 | Honeypot: `/backup_secrets/db_backup_2024.sql.bak` — curl | access.log — CRITICAL |
| 13:15:56 | 192.168.20.1 | Honeypot: `/backup_secrets/` — **Firefox** (manual) | access.log — CRITICAL |
| 13:17:04 | 192.168.20.1 | Honeypot: `/backup_secrets/db_backup_2024.sql.bak` — Firefox | access.log — CRITICAL |
| 14:07, 19:28 | 172.18.0.1 | Honeypot: `/backup_secrets/` ×2 — curl | access.log — CRITICAL |
| 19:54 | 192.168.20.1 | 13 login failures for `test@gmail.com` in under 1 second | access.log — WARNING |
| 20:02–20:19 | 192.168.20.1 | HOST_HEADER_ANOMALY ×3 — `test.com`, `192.168.20.12:4325` | access.log — WARNING |
| 20:40:50 | 172.18.0.1 | GET `/api/debug` and HOST_HEADER_ANOMALY `evil-attacker.com` | access.log — WARNING |

July 31 is the highest-volume day. The 19:54 credential stuffing (13 requests
for `test@gmail.com` in under one second) is automated tooling — human typing
cannot achieve sub-100ms timing across 13 requests. The honeypot was hit 9 times
across the day from both IPs, repeating the Firefox-then-curl discovery pattern
from July 24. The direct appearance of `192.168.20.12` as a source at 12:51 (not
the gateway) confirms the attacker connected directly from their LAN machine at
least once.

---

## 4. Vulnerability exploitation summary

### Vulnerability 1 — IDOR (EASY)

| Field | Value |
|---|---|
| First detected | Jul 28 08:38:39 UTC |
| Source | 172.18.0.1 |
| Method | Sequential ID enumeration via GET `/api/v1/users/<id>/setup-status` |
| Max distinct IDs read | 8 (users 1–8 enumerated in one session) |
| CRITICAL alerts fired | 11 (Jul 28: 9, Jul 30: 2) |
| Flag | `DRIFTLOCK{1d0r_1nt3rnal_ap1_3xp0s3d}` |

The attacker first probed with a username string (`voldamot`) — which returned
404 — then switched to sequential integers, confirming the endpoint accepts only
integer IDs. The systematic walk from ID 1 to 8 within 60 seconds is a complete
user-database enumeration.

### Vulnerability 2 — Information disclosure (MEDIUM)

| Field | Value |
|---|---|
| First detected | Jul 30 08:10 UTC |
| Sources | 172.18.0.1 (7 hits), 192.168.20.1 (4 hits) |
| Total accesses | 11 |
| Date range | Jul 30–31 |
| Flag | `DRIFTLOCK{d3bug_3ndp01nt_3xp0s3d}` |
| Data exposed | `python_version`, `platform`, `flask_env: development`, `app_secret_hint: "check .env file"` |

### Vulnerability 3 — Host Header Injection (HARD)

| Field | Value |
|---|---|
| First detected | Jul 30 13:26 UTC |
| Sources | 172.18.0.1, 192.168.20.1, 192.168.20.12 |
| Total injection attempts | 30+ |
| Date range | Jul 30–31 |
| Flag | `DRIFTLOCK{h0st_h34d3r_1nj3ct10n}` |

**Injected hosts used:**

| Injected host | Significance |
|---|---|
| `evil-attacker.com` | Primary attacker-controlled domain — flag route |
| `192.168.20.12:4325` | Attacker's own LAN address — realistic token-capture technique |
| `kien.com` | Named domain |
| `amimean.enough` | Test/novelty |
| `test.com` | Generic test |
| `localhost:4326` | Port-offset variant |

The `192.168.20.12:4325` injection is the most operationally realistic — it
redirects the victim's reset link to the attacker's own machine on the same port,
enabling silent token capture without an external domain.

---

## 5. Additional detected activity

### Honeypot — complete picture

| Date | Source | Hits | Tool | Notable |
|---|---|---|---|---|
| Jul 24 | 172.18.0.1 | 3 | Firefox + curl | First engagement — manual then scripted |
| Jul 28 | 192.168.20.1 | 20+ | Chrome + ZAP | Automated scanner — ZAP fingerprint paths |
| Jul 31 | 172.18.0.1 | 6 | curl/7.81.0 | Multiple sessions across the day |
| Jul 31 | 192.168.20.1 | 3 | curl/8.18.0 + Firefox | Discovery-then-automation again |

**Total honeypot events:** 30+ CRITICAL, across all four incident days.

### Credential attacks

| Date | Event | Count | Source |
|---|---|---|---|
| Jul 30 09:55–11:58 | MFA verify failures — `torvallds` | 30+ | 192.168.20.1 |
| Jul 30 10:02–10:03 | Login failures (no such user) | 4 | 192.168.20.1 |
| Jul 30 10:27, 11:41 | Login failures — `admin` | 2 | 192.168.20.1 |
| Jul 31 08:07–08:08 | Login failures (no such user) | 5 | 192.168.20.1 |
| Jul 31 19:54 | Login failures — `test@gmail.com` (<1 sec) | 13 | 192.168.20.1 |

These are not intentional CTF targets but represent real attack techniques
detected by the application's authentication warning infrastructure.

### TOTP replay events

The detections.log contains 5 `mfa_replay_suspected` events (Jul 24 ×2, Jul 28
×2, Jul 31 ×1). These were produced by a legacy detection helper from an earlier
version of the codebase. TOTP replay is not one of the three documented
intentional vulnerabilities — it is an accidental defect per the disclosure note.
The events are recorded here as additional detected activity.

---

## 6. How the attack was detected

- **Honeypot** — fired immediately and automatically on any `/backup_secrets/`
  hit; zero false positives; every hit CRITICAL.
- **IDOR CRITICAL alerts** — `idor_enumeration_suspected` fired at 3+ distinct
  IDs per source; the attacker triggered 11 CRITICAL alerts.
- **Debug WARNING events** — every `/api/debug` access logged at WARNING with
  source IP.
- **Host Header WARNING events** — every anomalous `Host` header logged with the
  injected value and flag; 30+ events created an unambiguous pattern.
- **Authentication WARNING events** — login failures, MFA failures, and lockout
  events captured credential-attack activity.
- **ELK centralized triage** — all logs shipped to Elasticsearch; Kibana
  dashboards enabled cross-log correlation confirming the same source IPs across
  honeypot, access, and internal-api indices across all four incident days.

---

## 7. Recommended fixes (production)

**Vulnerability 1 — IDOR:** enforce `requested_id == caller_id`; prefer
unguessable identifiers; do not expose internal APIs to untrusted networks.

**Vulnerability 2 — `/api/debug`:** remove the endpoint; disable Flask
`debug=True`.

**Vulnerability 3 — Host Header Injection:** build reset links from a configured
trusted base URL (`APP_URL`) rather than the incoming `Host` header; validate
`Host` against an allowlist (`EXPECTED_HOST`).

**Additional finding — `/api/profile` hardcoded token:** remove hardcoded
credentials; authenticate via session.

**Cross-cutting:** verify that account lockout engaged during the Jul 30
MFA brute-force (`torvallds`, 30+ failures). If lockout did not fire,
adjust the threshold. Production: WSGI server, HTTPS, secret manager, ELK
authentication.

All four are remediated and verified on the `patched` branch — see the
verification evidence in `reports/evidence/` and
`reports/Verification_Evidence_Appendix.md`.

---

## 8. Conclusion

The engagement demonstrated a complete, multi-day attack chain. The honeypot
provided the earliest high-confidence signal on day one. The ZAP scanner
signature on July 28 is the clearest recon evidence — unambiguous automated
tooling. All three documented vulnerabilities were exploited, detected, and
logged. The ELK pipeline enabled single-source correlation across all four
incident days and confirmed both attacker IPs.

The full detection-to-remediation cycle is evidenced: attack captured in logs,
flagged by detection rules, and closed on the `patched` branch with verified
fixes. SHA-256-checksummed log evidence is committed to
`reports/evidence/evidence-snapshot-20260731/`.