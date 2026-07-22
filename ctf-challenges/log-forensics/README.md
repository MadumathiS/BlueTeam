# Log Forensics Challenge Set

Three log-analysis challenges at increasing difficulty. Players search realistic,
noisy server logs to recover a hidden flag — reinforcing the same Blue Team log-
triage skills used in incident response.

## Structure

```
log-forensics/
├── easy/     detect_easy.log     + README (prompt + hints)
├── medium/   detect_medium.log   + README
├── hard/     detect_hard.log     + README
└── _graders/ answer_key.md       <-- KEEP PRIVATE, do not distribute
```

## Distributing to players

Hand each team ONLY the tier folder(s) you're releasing — e.g. `easy/` with its
`detect_easy.log` and `README.md`. **Never distribute `_graders/`.**

If using a scoreboard (e.g. CTFd): paste each README's scenario into the
challenge description, attach the `.log` file, set the flag as the accepted
answer, and add the hints as point-cost unlocks.

All challenge material stays on the isolated lab network.

## Flag format

`CTF{...}` — consistent across all three tiers.
