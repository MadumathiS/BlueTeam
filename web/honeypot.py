import json
import os
from datetime import datetime, timezone
from pathlib import Path

from flask import Blueprint, Response, current_app, request

from models import db

honeypot_bp = Blueprint("honeypot", __name__)

# Same base_dir convention app.py uses: repo_root/logs, one level up from
# web/. Kept self-contained here rather than importing app.py's base_dir
# so this module has no dependency on app.py's internals.
BASE_DIR = Path(__file__).resolve().parent.parent
LOGS_DIR = BASE_DIR / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)
HONEYPOT_LOG = LOGS_DIR / "honeypot.log"


class HoneypotLog(db.Model):
    """Maps to the `honeypot_logs` table created by db/init.sql. Defined
    here rather than in models.py so honeypot.py stays a single drop-in
    file with no edits required elsewhere — move it into models.py
    instead if you'd rather keep all models in one place; either works,
    just don't define it in both."""

    __tablename__ = "honeypot_logs"

    id = db.Column(db.BigInteger, primary_key=True)
    timestamp = db.Column(db.DateTime(timezone=True), nullable=False, server_default=db.func.now())
    severity = db.Column(db.String(20), nullable=False, default="CRITICAL")
    source_ip = db.Column(db.String(64))
    path = db.Column(db.String(255), nullable=False)
    user_agent = db.Column(db.Text)
    details = db.Column(db.Text)

# Embedded rather than read from honeypot/backup_secrets/ on disk — the
# `web` container has no reason to have that folder mounted, and a
# hardcoded decoy means this module has zero filesystem dependencies
# outside logs/.
DECOY_BACKUP_CONTENT = """\
-- MySQL dump 10.13  Distrib 8.0.34
-- Host: prod-db-01.internal    Database: driftlock
-- ------------------------------------------------------
-- Table structure for table `users`

CREATE TABLE `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(64) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `totp_secret` varchar(64) NOT NULL,
  PRIMARY KEY (`id`)
);

-- Dumping data for table `users`
INSERT INTO `users` VALUES
(1,'admin','$2b$12$decoyhashdecoyhashdecoyhashdecoyhashde','JBSWY3DPEHPK3PXPDECOY'),
(2,'svc_backup','$2b$12$decoyhashdecoyhashdecoyhashdecoyhashde','KRSXG5CTMVSXGZDBDECOY');

-- Dump completed -- THIS IS A DECOY FILE. If you can read this, an
-- intrusion detection alert has already been filed against your session.
"""


def _log_hit(path: str):
    """Write the alert to the log file (always), the app logger (always),
    then attempt a DB insert (best-effort — never let this raise)."""
    source_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    user_agent = request.headers.get("User-Agent", "unknown")
    details = f"Request for disallowed path listed in robots.txt: {path}"

    entry = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "event": "honeypot_hit",
        "severity": "CRITICAL",
        "source_ip": source_ip,
        "path": path,
        "user_agent": user_agent,
        "details": details,
    }
    line = json.dumps(entry)
    with open(HONEYPOT_LOG, "a") as f:
        f.write(line + "\n")
    current_app.logger.warning("HONEYPOT ALERT: %s", line)

    try:
        db.session.add(HoneypotLog(
            severity="CRITICAL",
            source_ip=source_ip,
            path=path,
            user_agent=user_agent,
            details=details,
        ))
        db.session.commit()
    except Exception as e:
        # A DB hiccup must never break the trap route or mask the alert —
        # the file + logger writes above already captured it. Roll back
        # so this session isn't left in a broken transaction state for
        # whatever request handles it next.
        db.session.rollback()
        current_app.logger.warning(f"honeypot_logs DB write failed (non-fatal): {e}")


@honeypot_bp.route("/robots.txt")
def robots_txt():
    """Serves the real web/robots.txt file so editing that file doesn't
    require a code change here."""
    robots_path = Path(current_app.root_path) / "robots.txt"
    if robots_path.exists():
        return Response(robots_path.read_text(), mimetype="text/plain")
    # Fallback if the file's missing, so the bait still exists.
    return Response("User-agent: *\nDisallow: /backup_secrets/\n", mimetype="text/plain")


@honeypot_bp.route("/backup_secrets/")
def backup_secrets_index():
    _log_hit("/backup_secrets/")
    return Response(
        "Index of /backup_secrets/\n\ndb_backup_2024.sql.bak\n",
        mimetype="text/plain",
    )


@honeypot_bp.route("/backup_secrets/<path:filename>")
def backup_secrets_file(filename):
    _log_hit(f"/backup_secrets/{filename}")
    return Response(DECOY_BACKUP_CONTENT, mimetype="text/plain")
