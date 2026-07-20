"""
DriftLock — internal-api service.
Deliberately-exposed internal API (own host port) for Red Team discovery.
Shares the web service's PostgreSQL database.

INTENTIONAL VULNERABILITY (HARD): IDOR / broken access control.
  GET /api/v1/users/<user_id>/setup-status
  Returns another user's account metadata when <user_id> is manipulated,
  with no authorization check. Documented CTF target; lab use only.
"""

import os
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote_plus

from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

db_user = os.getenv("DB_USER", "driftlock_admin")
db_pass = os.getenv("DB_PASSWORD", "devpass")
db_host = os.getenv("DB_HOST", "db")
db_port = os.getenv("DB_PORT", "5432")
db_name = os.getenv("DB_NAME", os.getenv("POSTGRES_DB", "driftlock"))

app.config["SQLALCHEMY_DATABASE_URI"] = (
    f"postgresql://{db_user}:{quote_plus(db_pass)}@{db_host}:{db_port}/{db_name}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50))
    email = db.Column(db.String(255))
    mfa_enabled = db.Column(db.Boolean)
    created_at = db.Column(db.DateTime)


LOGS_DIR = Path(os.getenv("LOGS_DIR", "/app/logs"))
LOGS_DIR.mkdir(parents=True, exist_ok=True)
API_LOG = LOGS_DIR / "internal-api.log"

_access_by_ip = {}


def _write_log(entry: dict):
    with open(API_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")


def _source_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr)


@app.before_request
def log_request():
    _write_log({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": "request",
        "source_ip": _source_ip(),
        "method": request.method,
        "path": request.path,
        "user_agent": request.headers.get("User-Agent", "unknown"),
    })


@app.route("/")
def index():
    return jsonify({
        "service": "driftlock-internal-api",
        "version": "v1",
        "endpoints": ["/api/v1/users/<id>/setup-status"],
    })


@app.route("/api/status")
def status():
    return jsonify({"status": "ok"})


@app.route("/api/v1/users/<int:user_id>/setup-status")
def user_setup_status(user_id):
    user = User.query.get(user_id)
    if not user:
        _write_log({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": "setup_status_notfound",
            "source_ip": _source_ip(),
            "requested_id": user_id,
        })
        return jsonify({"error": "Not found"}), 404

    ip = _source_ip()
    seen = _access_by_ip.setdefault(ip, set())
    seen.add(user_id)

    detection = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": "setup_status_access",
        "source_ip": ip,
        "requested_id": user_id,
        "distinct_ids_seen": len(seen),
    }
    if len(seen) >= 3:
        detection["event"] = "idor_enumeration_suspected"
        detection["severity"] = "CRITICAL"
        detection["details"] = (
            "Single source read multiple distinct user IDs — likely IDOR enumeration"
        )
    _write_log(detection)

    return jsonify({
        "user_id": user.id,
        "username": user.username,
        "mfa_enabled": user.mfa_enabled,
        "created_at": user.created_at.isoformat() if user.created_at else None,
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)