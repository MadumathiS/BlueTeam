from flask import Flask, render_template, request, jsonify, abort, has_request_context
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
import sys
import platform
import re
import os
from crypto_utils import hash_password, encrypt_secret
from models import db, User
import pyotp
from pathlib import Path
from urllib.parse import urlparse
import psycopg2
import time

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'DATABASE_URL', 'postgresql://driftlock_admin:devpass@localhost:5433/driftlock'
)


def ensure_database_exists(database_url, retries=5, delay=2):
    """Ensure the target Postgres database exists; create it if missing.

    This connects to the server's default `postgres` database and issues
    a CREATE DATABASE if needed. Retries a few times to wait for the
    server to be ready.
    """
    parsed = urlparse(database_url)
    target_db = parsed.path.lstrip('/') or 'postgres'
    user = parsed.username or os.getenv('POSTGRES_USER')
    password = parsed.password or os.getenv('POSTGRES_PASSWORD')
    host = parsed.hostname or 'localhost'
    port = parsed.port or 5432

    for attempt in range(retries):
        try:
            conn = psycopg2.connect(dbname='postgres', user=user, password=password, host=host, port=port)
            conn.autocommit = True
            cur = conn.cursor()
            cur.execute("SELECT 1 FROM pg_database WHERE datname=%s;", (target_db,))
            if not cur.fetchone():
                cur.execute('CREATE DATABASE "{}";'.format(target_db))
                app.logger.info(f"Created database {target_db}")
            cur.close()
            conn.close()
            return
        except Exception as e:
            # Wait and retry while DB container starts
            app.logger.warning(f"Database not ready yet ({e}), retrying in {delay}s...")
            time.sleep(delay)
    app.logger.error(f"Could not ensure database {target_db} exists after {retries} attempts")


ensure_database_exists(app.config['SQLALCHEMY_DATABASE_URI'])
db.init_app(app)


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
# Configure storage for Flask-Limiter (prefer Redis in production)
ratelimit_uri = os.getenv('RATELIMIT_STORAGE_URI')
if ratelimit_uri:
    limiter = Limiter(app=app, key_func=get_remote_address, default_limits=["100 per minute"], storage_uri=ratelimit_uri)
else:
    limiter = Limiter(app=app, key_func=get_remote_address, default_limits=["100 per minute"])  # falls back to in-memory

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

@app.route('/api/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')

    if not is_valid_username(username) or len(password) < 8:
        return jsonify({"error": "Invalid username or password"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already exists"}), 409

    totp_secret = pyotp.random_base32()
    user = User(
        username=username,
        password_hash=hash_password(password),
        totp_secret_encrypted=encrypt_secret(totp_secret)
    )
    db.session.add(user)
    db.session.commit()

    app.logger.info(f"New user registered: {username}")

    # In real flow, show this as a QR code for scanning into an authenticator app
    provisioning_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
        name=username, issuer_name="BlueTeamPortal"
    )
    return jsonify({"message": "Registered", "provisioning_uri": provisioning_uri})

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