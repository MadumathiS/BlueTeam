# Log Forensics — Broken in Two (Hard)

**Category:** Forensics / Log Analysis
**Difficulty:** Hard
**Points:** 500

## Scenario

The flag was written to the logs during an incident — but not in one piece, and
not in plain sight. Whoever logged it scattered the evidence. A single fragment
is only half the story.

## Your Task

Recover and reconstruct the flag hidden in `detect_hard.log`.

## Files

- `detect_hard.log`

## Flag Format

`CTF{...}`

---

### Hints (ask a grader to unlock — costs points)

<details>
<summary>Hint 1</summary>

The flag is split into labelled fragments. Find every fragment before you try to
read anything.
</details>

<details>
<summary>Hint 2</summary>

Order matters. The fragments are numbered — reassemble them in sequence. Watch
out for decoy blobs that look similar but aren't labelled the same way.
</details>

<details>
<summary>Hint 3</summary>

What you reassemble still isn't human-readable. It has been encoded — decode it
to reveal the flag.
</details>
