# Log Forensics — Signal in the Noise (Medium)

**Category:** Forensics / Log Analysis
**Difficulty:** Medium
**Points:** 250

## Scenario

A busy web server produced hundreds of log lines during an incident. Buried in
the traffic is a single marker left by the analyst. The catch: the logs are
noisy, and not everything that looks interesting is the flag.

## Your Task

Find the flag hidden among the ~500 lines of `detect_medium.log`.

## Files

- `detect_medium.log`

## Flag Format

`CTF{...}`

---

### Hints (ask a grader to unlock — costs points)

<details>
<summary>Hint 1</summary>

Scrolling won't cut it here. Filter the file down to what matters.
</details>

<details>
<summary>Hint 2</summary>

Not everything wrapped in braces `{ }` is the flag — some lines carry decoy
tokens. Match the flag's exact shape, not just any brace pair.
</details>
