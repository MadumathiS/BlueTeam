from flask import Flask, redirect, render_template, url_for, session, request, jsonify, abort, has_request_context
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
import sys
import platform
import os
from models import db
from pathlib import Path
from urllib.parse import urlparse
import psycopg2
import time
from urllib.parse import quote_plus
from auth import register as register_handler
from mfa import totp_bp
from auth import confirm_mfa_setup as confirm_mfa_handler



app = Flask(__name__)

# Build SQLALCHEMY_DATABASE_URI safely from env vars to avoid parsing issues
env_db_url = os.getenv('DATABASE_URL')
# If DB_PASSWORD is provided via env, prefer building the URL from components
# This avoids issues when the password contains characters like '@' that break parsing
if env_db_url and not os.getenv('DB_PASSWORD'):
    app.config['SQLALCHEMY_DATABASE_URI'] = env_db_url
else:
    db_user = os.getenv('DB_USER', 'driftlock_admin')
    db_pass = os.getenv('DB_PASSWORD', 'devpass')
    db_host = os.getenv('DB_HOST', 'db')
    db_port = os.getenv('DB_PORT', '5432')
    db_name = os.getenv('DB_NAME', os.getenv('POSTGRES_DB', 'driftlock'))
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

from honeypot import honeypot_bp
app.register_blueprint(honeypot_bp)

# --- Logging setup (for Incident Response Report) ---
# Ensure logs directory exists (relative to project BlueTeam/)
LOGS_DIR = Path(os.getenv('LOGS_DIR', '/app/logs'))
LOGS_DIR.mkdir(parents=True, exist_ok=True)
logfile = str(LOGS_DIR / 'access.log')

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

# --- Normal routes ---
@app.route('/')
@app.route('/home')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET'])
def login():
    return render_template('login.html')

register_view = limiter.limit("5 per minute")(register_handler)
app.add_url_rule('/register', endpoint='register', view_func=register_view, methods=['GET', 'POST'])
app.add_url_rule('/api/register', endpoint='api_register', view_func=register_view, methods=['POST'])
app.add_url_rule('/register/confirm-mfa', endpoint='confirm_mfa_setup',
                  view_func=confirm_mfa_handler, methods=['POST'])

@app.route('/support', methods=['GET'])    
def support_page():
    return render_template('support.html')
# --- Register the TOTP Blueprint for MFA routes ---
app.register_blueprint(totp_bp)

@app.route('/admin/dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    # Placeholder for admin dashboard logic
    return render_template('admin_dashboard.html')  

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

@app.errorhandler(500) #manage internal server errors
def internal_error(e):
    app.logger.error(f"Unhandled exception: {e}")
    return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=4325, debug=True) #remove debug true in production