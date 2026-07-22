# Log Forensics — Answer Key (GRADERS ONLY)

> Do NOT include this folder in anything handed to players.
> Keep `_graders/` out of the distributed challenge package.

---

## Easy — Needle in the Log

**Flag:** `CTF{L0G_GR3P_EASY}`

**Intended solve:**
```bash
grep -aoE 'CTF\{[^}]+\}' detect_easy.log
```
The flag sits in plain text on an "analyst note" line (~line 28) among normal
access log entries. Tests basic log searching.

---

## Medium — Signal in the Noise

**Flag:** `CTF{N015Y_L0G_M3D1UM}`

**Intended solve:**
```bash
grep -aoE 'CTF\{[^}]+\}' detect_medium.log
```
The flag is on one WARNING line (~line 362) deep in ~500 noisy entries, on a
`GET /api/debug` request with an Nmap user-agent. Decoy `session={NNNNNN}`
tokens defeat a lazy `grep '{'`; players must match the `CTF{...}` pattern.
Tests signal-in-noise triage.

---

## Hard — Broken in Two

**Flag:** `CTF{L0G_F0R3N51C5_H4RD}`

**Intended solve:**
```bash
# 1) Find both labelled fragments (ignore unlabelled decoy token= blobs):
grep -aoE 'part=[12]/2 id=b64flag\]=[A-Za-z0-9+/=]+' detect_hard.log

#    part=1/2 -> Q1RGe0wwR19GMFIz   (~line 189)
#    part=2/2 -> TjUxQzVfSDRSRH0=   (~line 567)

# 2) Concatenate in order and base64-decode:
echo 'Q1RGe0wwR19GMFIzTjUxQzVfSDRSRH0=' | base64 -d
```
Output: `CTF{L0G_F0R3N51C5_H4RD}`

The two halves are ~380 lines apart, tagged `debug_fragment[part=1/2 id=b64flag]`
and `part=2/2`. Decoy `token=<base64>` blobs are scattered to mislead. Tests
correlation + decoding (forensics with a light crypto step).

---

## Scoreboard summary

| Tier   | Flag                     | Points | Skill tested              |
|--------|--------------------------|--------|---------------------------|
| Easy   | `CTF{L0G_GR3P_EASY}`     | 100    | Basic log search (grep)   |
| Medium | `CTF{N015Y_L0G_M3D1UM}`  | 250    | Signal-in-noise triage    |
| Hard   | `CTF{L0G_F0R3N51C5_H4RD}`| 500    | Correlation + decoding    |
