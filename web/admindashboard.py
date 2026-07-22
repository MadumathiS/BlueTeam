"""
admindashboard.py — DriftLock admin + user activity views.

Two Flask blueprints:
  admin_bp  -> /admin/dashboard : system-wide logs, alerts, user activity.
               Restricted by @admin_required (User.role == 'A').
  alerts_bp -> /activity        : per-user security events, scoped to the
               logged-in user's own account (@login_required).

Data sources:
  - activity_logs  (DB)  : application access/auth events
  - honeypot_logs  (DB)  : CRITICAL honeypot trips
  - detections.log (file): TOTP-replay / structured detections (JSON lines)
  - internal-api.log (file): IDOR-enumeration alerts (JSON lines)

All admin queries are system-wide; all /activity queries are filtered by the
session user_id and never accept an id from the request, so a user can only
ever see their own events.
"""
import json
import os
from pathlib import Path

from flask import Blueprint, render_template, session, jsonify

from models import db, User, ActivityLog
from decorators import login_required, admin_required

# HoneypotLog is defined in honeypot.py; import defensively so this module
# still loads if import order ever changes.
try:
    from honeypot import HoneypotLog
except Exception:
    HoneypotLog = None

LOGS_DIR = Path(os.getenv("LOGS_DIR", "/app/logs"))
DETECTIONS_LOG = LOGS_DIR / "detections.log"
INTERNAL_API_LOG = LOGS_DIR / "internal-api.log"

admin_bp = Blueprint("admin", __name__)
alerts_bp = Blueprint("alerts", __name__)


# ---------- helpers ----------

def _read_json_lines(path, limit=200):
    """Read a JSON-lines log file safely, newest last. Returns [] on any
    problem — a missing or half-written log must never 500 the dashboard."""
    if not path.exists():
        return []
    entries = []
    try:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue  # skip a partially-flushed line
    except OSError:
        return []
    return entries[-limit:]


def _serialize_activity(row):
    return {
        "id": row.id,
        "user_id": row.user_id,
        "action": row.action,
        "status": row.status,
        "ip_address": row.ip_address,
        "user_agent": row.user_agent,
        "request_path": row.request_path,
        "timestamp": row.timestamp.isoformat() if row.timestamp else None,
    }


# ---------- ADMIN: system-wide ----------

@admin_bp.route("/admin/dashboard", methods=["GET"])
@admin_required
def admin_dashboard():
    """HTML shell; data is loaded client-side from the JSON endpoint below."""
    return render_template("admin_dashboard.html")


@admin_bp.route("/admin/api/overview", methods=["GET"])
@admin_required
def admin_overview():
    """System-wide view: summary counts, recent activity across all users,
    honeypot hits, and the high-signal detection events."""
    recent_activity = (
        ActivityLog.query
        .order_by(ActivityLog.timestamp.desc())
        .limit(100)
        .all()
    )

    honeypot_hits = []
    if HoneypotLog is not None:
        try:
            honeypot_hits = [
                {
                    "id": h.id,
                    "timestamp": h.timestamp.isoformat() if h.timestamp else None,
                    "severity": h.severity,
                    "source_ip": h.source_ip,
                    "path": h.path,
                    "user_agent": h.user_agent,
                    "details": h.details,
                }
                for h in HoneypotLog.query
                    .order_by(HoneypotLog.timestamp.desc())
                    .limit(50)
                    .all()
            ]
        except Exception:
            db.session.rollback()
            honeypot_hits = []

    detections = _read_json_lines(DETECTIONS_LOG, limit=100)
    internal_api = _read_json_lines(INTERNAL_API_LOG, limit=100)

    replay_alerts = [d for d in detections
                     if d.get("event") == "mfa_replay_suspected"]
    idor_alerts = [e for e in internal_api
                   if e.get("event") == "idor_enumeration_suspected"]

    total_users = User.query.count()
    mfa_users = User.query.filter_by(mfa_enabled=True).count()

    return jsonify({
        "summary": {
            "total_users": total_users,
            "mfa_enabled_users": mfa_users,
            "honeypot_hits": len(honeypot_hits),
            "replay_alerts": len(replay_alerts),
            "idor_alerts": len(idor_alerts),
        },
        "recent_activity": [_serialize_activity(r) for r in recent_activity],
        "honeypot_hits": honeypot_hits,
        "replay_alerts": replay_alerts,
        "idor_alerts": idor_alerts,
    })


@admin_bp.route("/admin/api/users", methods=["GET"])
@admin_required
def admin_users():
    """Account roster with MFA + role status — admin only."""
    users = User.query.order_by(User.created_at.desc()).all()
    return jsonify({
        "users": [
            {
                "id": u.id,
                "username": u.username,
                "email": u.email,
                "mfa_enabled": u.mfa_enabled,
                "is_admin": u.is_admin,
                "created_at": u.created_at.isoformat() if u.created_at else None,
            }
            for u in users
        ]
    })


# ---------- USER: own account only ----------

@alerts_bp.route("/activity", methods=["GET"])
@login_required
def activity_alerts():
    """Per-user activity alerts page (HTML shell)."""
    return render_template("activity_alerts.html")


@alerts_bp.route("/activity/api/mine", methods=["GET"])
@login_required
def my_activity():
    """Security-relevant events for the LOGGED-IN user only.

    Every query is filtered by the session user_id — no id is ever read from
    the request, so a user cannot pivot to another account's events.
    """
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Not authenticated"}), 401

    my_events = (
        ActivityLog.query
        .filter_by(user_id=user_id)
        .order_by(ActivityLog.timestamp.desc())
        .limit(50)
        .all()
    )

    my_detections = [
        d for d in _read_json_lines(DETECTIONS_LOG, limit=500)
        if d.get("user_id") == user_id
    ]

    return jsonify({
        "activity": [_serialize_activity(r) for r in my_events],
        "security_events": my_detections,
    })
