"""
Blue Team detection helpers.

Writes structured JSON detection events to logs/detections.log, which Logstash
ships into Elasticsearch for Kibana triage — the same pattern as honeypot.log
and internal-api.log.

Currently detects:
  - TOTP replay: the same 30-second time window (counter) accepted more than
    once for a user. This is the Blue-side signal for intentional
    Vulnerability 2 (TOTP codes are not invalidated after use).
"""

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

LOGS_DIR = Path(os.getenv("LOGS_DIR", "/app/logs"))
LOGS_DIR.mkdir(parents=True, exist_ok=True)
DETECT_LOG = LOGS_DIR / "detections.log"

# Touch the file on module load so Filebeat/Logstash find it immediately
DETECT_LOG.touch(exist_ok=True)

# Recently-seen TOTP counters per user.
_used_counters = {}

# How many recent counters to remember per user (keeps memory bounded).
_MAX_REMEMBERED = 10


def _write(entry: dict) -> None:
    try:
        with open(DETECT_LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        print(f"[ERROR] Failed writing to {DETECT_LOG}: {e}", flush=True)


def record_totp_use(user_id, source_ip, context="login"):
    """Record a successful TOTP verification and flag replays.

    Call this AFTER a code has been accepted. Returns True if the code's time
    window had already been used for this user (i.e. a suspected replay).
    """
    counter = int(time.time()) // 30  # 30-second TOTP window

    seen = _used_counters.setdefault(user_id, [])
    is_replay = counter in seen

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": "mfa_replay_suspected" if is_replay else "mfa_verify",
        "user_id": user_id,
        "counter": counter,
        "source_ip": source_ip,
        "context": context,
    }

    if is_replay:
        entry["severity"] = "HIGH"
        entry["details"] = (
            "A one-time TOTP code was accepted more than once within the same "
            "time window — possible captured-code replay."
        )

    seen.append(counter)
    if len(seen) > _MAX_REMEMBERED:
        del seen[-_MAX_REMEMBERED:]

    _write(entry)
    return is_replay