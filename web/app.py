from flask import Flask, render_template, request, jsonify, abort, has_request_context
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
import sys
import platform
import re
import os
from pathlib import Path

app = Flask(__name__)

# --- Logging setup (for Incident Response Report) ---
# Ensure logs directory exists (relative to project BlueTeam/)
base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
logs_dir = os.path.join(base_dir, 'logs')
Path(logs_dir).mkdir(parents=True, exist_ok=True)
logfile = os.path.join(logs_dir, 'access.log')

logging.basicConfig(
    filename=logfile,
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s'
)
# --- Format of the logging ---
class RequestFormatter(logging.Formatter):
    def format(self, record):
        # Avoid accessing `request` when outside an active request context
        if has_request_context():
            record.remote_addr = request.remote_addr
            record.method = request.method
            record.path = request.path
        else:
            record.remote_addr = 'N/A'
            record.method = 'N/A'
            record.path = 'N/A'
        return super().format(record)

handler = logging.FileHandler(logfile)
handler.setFormatter(RequestFormatter(
    '%(asctime)s | %(levelname)s | %(remote_addr)s | %(method)s %(path)s'
))
app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)

# --- Rate limiting (security control) ---
limiter = Limiter(app=app, key_func=get_remote_address, default_limits=["100 per minute"])

@app.before_request
def log_request():
    app.logger.info("Incoming request")

# --- Input validation helper ---
def is_valid_username(username):
    return bool(re.match(r'^[a-zA-Z0-9_]{3,20}$', username))

# --- Normal routes ---
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/status')
def status():
    return jsonify({"status": "ok"})

# --- Authenticated endpoint example (security control: auth required) ---
@app.route('/api/profile')
@limiter.limit("10 per minute")
def profile():
    token = request.headers.get('Authorization')
    if token != "Bearer valid-session-token-123":
        app.logger.warning(f"Unauthorized access attempt to /api/profile from {request.remote_addr}")
        abort(401)
    return jsonify({"user": "demo_user", "role": "member"})

# --- INTENTIONAL VULNERABILITY: exposed debug endpoint, no auth required ---
@app.route('/api/debug')
def debug():
    app.logger.warning(f"Debug endpoint accessed by {request.remote_addr}")
    return jsonify({
        "python_version": sys.version,
        "platform": platform.platform(),
        "flask_env": "development",
        "app_secret_hint": "check .env file"  # intentionally leaky
    })

@app.errorhandler(401)
def unauthorized(e):
    return jsonify({"error": "Unauthorized"}), 401

@app.errorhandler(404)
def not_found(e):
    app.logger.info(f"404 hit: {request.path} from {request.remote_addr}")
    return jsonify({"error": "Not found"}), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=4325)