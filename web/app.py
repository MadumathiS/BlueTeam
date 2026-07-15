from flask import Flask, redirect, render_template, url_for, session, request, jsonify, abort, has_request_context
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
import sys
import platform
import re
import os
from crypto_utils import hash_password, encrypt_secret
from models import db, User, TOTPSeed, PasswordResetToken, ActivityLog
import json
import pyotp
from pathlib import Path
from urllib.parse import urlparse
import psycopg2
import time
from urllib.parse import quote_plus

app = Flask(__name__)

# Build SQLALCHEMY_DATABASE_URI safely from env vars to avoid parsing issues
env_db_url = os.getenv('DATABASE_URL')
# If DB_PASSWORD is provided via env, prefer building the URL from components
# This avoids issues when the password contains characters like '@' that break parsing
if env_db_url and not os.getenv('DB_PASSWORD'):
    app.config['SQLALCHEMY_DATABASE_URI'] = env_db_url
else:
    db_user = os.getenv('DB_USER')
    db_pass = os.getenv('DB_PASSWORD')
    db_host = os.getenv('DB_HOST')
    db_port = os.getenv('DB_PORT')
    db_name = os.getenv('DB_NAME')
    safe_pass = quote_plus(db_pass)
    constructed = f"postgresql://{db_user}:{safe_pass}@{db_host}:{db_port}/{db_name}"
    app.logger.info(f"Using database URL: postgresql://{db_user}:***@{db_host}:{db_port}/{db_name}")
    app.config['SQLALCHEMY_DATABASE_URI'] = constructed


def ensure_database_exists(database_url, retries=5, delay=2):
    """Ensure the target Postgres database exists; create it if missing.

    This connects to the server's default `postgres` database and issues
    a CREATE DATABASE if needed. Retries a few times to wait for the
    server to be ready.
    """
    parsed = urlparse(database_url)
    target_db = parsed.path.lstrip('/') or 'postgres'
    user = parsed.username or os.getenv('DB_USER')
    password = parsed.password or os.getenv('DB_PASSWORD')
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


if os.getenv('ENSURE_DATABASE_EXISTS', '0') == '1':
    ensure_database_exists(app.config['SQLALCHEMY_DATABASE_URI'])
db.init_app(app)

with app.app_context():
    db.create_all()


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

def is_valid_email(email):
    return bool(re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', email))

# --- Normal routes ---
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET'])
def login_page():
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
@app.route('/api/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    if session.get('logged_in'):
        return redirect(url_for('home'))

    if request.method == 'GET':
        return render_template('register.html')

    # --- POST request handling ---
    print("Register endpoint hit")

    if request.is_json:
        data = request.get_json(silent=True) or {}
    else:
        data = request.form.to_dict(flat=True)

    if not data or not isinstance(data, dict):
        return jsonify({"error": "Invalid or missing request body"}), 400

    username = str(data.get('username', '')).strip()
    email = str(data.get('email', '')).strip().lower()
    password = data.get('password', '')
    confirm_password = data.get('confirm_password', '')

    if not isinstance(password, str):
        password = ''
    if not isinstance(confirm_password, str):
        confirm_password = ''

    # Input validation
    if not email:
        return jsonify({"error": "Email is required"}), 400
    if not is_valid_email(email):
        return jsonify({"error": "Invalid email format"}), 400
    if not is_valid_username(username):
        return jsonify({"error": "Invalid username format"}), 400
    if not isinstance(password, str) or len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    if password != confirm_password:
        return jsonify({"error": "Passwords do not match"}), 400

    try:
        # Check for existing user
        if User.query.filter_by(username=username).first():
            app.logger.warning(f"Duplicate registration attempt: {username} from {request.remote_addr}")
            return jsonify({"error": "Username already exists"}), 409
        if User.query.filter_by(email=email).first():
            app.logger.warning(f"Duplicate email registration attempt: {email} from {request.remote_addr}")
            return jsonify({"error": "Email already exists"}), 409

        # Create the user
        new_user = User(
            username=username,
            email=email,
            password_hash=hash_password(password),
            mfa_enabled=False
        )
        db.session.add(new_user)
        db.session.flush()  # gets new_user.id before commit, without ending the transaction

        # Generate TOTP secret + backup codes
        totp_secret = pyotp.random_base32()
        backup_codes = [pyotp.random_base32()[:8] for _ in range(5)]

        new_seed = TOTPSeed(
            user_id=new_user.id,
            encrypted_seed=encrypt_secret(totp_secret),
            backup_codes=json.dumps(backup_codes)
        )
        db.session.add(new_seed)
        db.session.commit()

        app.logger.info(f"New user registered: {username}")

        # Provisioning URI - used to generate the QR code for authenticator apps
        provisioning_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
            name=username, issuer_name="DriftlockPortal"
        )

        return jsonify({
            "message": "User registered successfully",
            "provisioning_uri": provisioning_uri,
            "backup_codes": backup_codes  # shown once, user should save these
        }), 201
    except Exception as e:
        app.logger.exception("Error during registration: %s", e)
        test = e
        print (test)
        print(f"Error during registration: {e}", flush=True)
        db.session.rollback()
        return jsonify({"error": "Internal server error", "detail": str(e)}), 500


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
    app.run(host='0.0.0.0', port=4325, debug=True) #remove debug true in production