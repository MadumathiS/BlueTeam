from flask import Flask, request, jsonify, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
import sys
import platform
import re

app = Flask(__name__)

# --- Logging setup (for Incident Response Report) ---
logging.basicConfig(
    filename='logs/access.log',
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s'
)

class RequestFormatter(logging.Formatter):
    def format(self, record):
        record.remote_addr = request.remote_addr if request else 'N/A'
        record.method = request.method if request else 'N/A'
        record.path = request.path if request else 'N/A'
        return super().format(record)

handler = logging.FileHandler('logs/access.log')
handler.setFormatter(RequestFormatter(
    '%(asctime)s | %(levelname)s | %(remote_addr)s | %(method)s %(path)s'
))
app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)

# --- Rate limiting (security control) ---
limiter = Limiter(get_remote_address, app=app, default_limits=["100 per minute"])

@app.before_request
def log_request():
    app.logger.info("Incoming request")

# --- Input validation helper ---
def is_valid_username(username):
    return bool(re.match(r'^[a-zA-Z0-9_]{3,20}$', username))

# --- Normal routes ---
@app.route('/')
def home():
    return "Welcome to the Blue Team app."

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