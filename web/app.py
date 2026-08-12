from flask import Flask, redirect, render_template, url_for, session, request, jsonify, abort, has_request_context
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
import sys
import platform
import os
from models import db, User
from pathlib import Path
from urllib.parse import urlparse
import psycopg2
import time
from urllib.parse import quote_plus
from datetime import datetime

from auth import (
    register as register_handler,
    login as login_handler,
    logout as logout_handler,
    verify_mfa as verify_mfa_handler,
    confirm_mfa_setup as confirm_mfa_handler,
    resend_mfa as resend_mfa_handler
)
from mfa import totp_bp
from reset import request_reset, reset_password as reset_password_handler
from admindashboard import admin_bp, alerts_bp


app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
if not app.secret_key:
    raise RuntimeError("SECRET_KEY is not set")

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
# Single handler, single format. No basicConfig (it caused duplicate/bare lines),
# and propagate=False so nothing is written twice.
LOGS_DIR = Path(os.getenv('LOGS_DIR', '/app/logs'))
LOGS_DIR.mkdir(parents=True, exist_ok=True)
logfile = str(LOGS_DIR / 'access.log')


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


app.logger.handlers.clear()
handler = logging.FileHandler(logfile)
handler.setFormatter(RequestFormatter(
    '%(asctime)s | %(levelname)s | %(remote_addr)s | %(method)s %(path)s | %(message)s'
))
app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)
app.logger.propagate = False

# --- Rate limiting (security control) ---
# Configure storage for Flask-Limiter (prefer Redis in production)
ratelimit_uri = os.getenv('RATELIMIT_STORAGE_URI')
if ratelimit_uri:
    limiter = Limiter(app=app, key_func=get_remote_address, default_limits=["100 per minute"], storage_uri=ratelimit_uri)
else:
    limiter = Limiter(app=app, key_func=get_remote_address, default_limits=["100 per minute"])  # falls back to in-memory

@app.context_processor
def inject_user_status():
    pending_setup_id = session.get('pending_setup_user_id')
    if 'user_id' in session:
        current_username = User.query.get(session['user_id']).username
    elif pending_setup_id:
        current_username = User.query.get(pending_setup_id).username
    else:
        current_username = None
    return {
        'is_logged_in': session.get('logged_in', False),
        'is_pending_setup': bool(pending_setup_id),
        'current_username': current_username
    }

# --- Normal routes ---
@app.route('/')
@app.route('/home')
def home():
    return render_template('index.html')


register_view = limiter.limit("5 per minute")(register_handler)
app.add_url_rule('/register', endpoint='register', view_func=register_view, methods=['GET', 'POST'])
app.add_url_rule('/reset-password', endpoint='reset_request',
                 view_func=request_reset, methods=['GET', 'POST'])
app.add_url_rule('/api/reset-password', endpoint='api_reset_request',
                 view_func=request_reset, methods=['POST'])
app.add_url_rule('/reset-password/<token>', endpoint='reset_password',
                 view_func=reset_password_handler, methods=['GET', 'POST'])
app.add_url_rule('/api/reset-password/<token>', endpoint='api_reset_password',
                 view_func=reset_password_handler, methods=['POST'])
app.add_url_rule('/api/register', endpoint='api_register', view_func=register_view, methods=['POST'])


def login_key():
    if request.is_json:
        data = request.get_json(silent=True) or {}
    else:
        data = request.form
    username = (data.get('username') or '').strip().lower()
    return username or get_remote_address()


login_view = limiter.limit(
    "3 per minute",
    key_func=login_key,
    deduct_when=lambda response: response.status_code == 401
)(login_handler)
app.add_url_rule('/login', endpoint='login', view_func=login_view, methods=['GET', 'POST'])
app.add_url_rule('/api/login', endpoint='api_login', view_func=login_view, methods=['POST'])
app.add_url_rule('/logout', endpoint='logout', view_func=logout_handler, methods=['GET'])

verify_mfa_view = limiter.limit("5 per minute")(verify_mfa_handler)
app.add_url_rule('/verify-mfa', endpoint='verify_mfa', view_func=verify_mfa_view, methods=['GET', 'POST'])
app.add_url_rule('/api/verify-mfa', endpoint='api_verify_mfa', view_func=verify_mfa_view, methods=['POST'])
app.add_url_rule('/api/resend-mfa', endpoint='resend_mfa', view_func=resend_mfa_handler, methods=['POST'])

app.add_url_rule('/register/confirm-mfa', endpoint='confirm_mfa_setup',
                 view_func=confirm_mfa_handler, methods=['POST'])


@app.route('/support', methods=['GET'])
def support_page():
    return render_template('support.html')


# --- Register the TOTP Blueprint for MFA routes ---
app.register_blueprint(totp_bp)

# --- Register the admin dashboard + user activity blueprints ---
# admin_bp  : /admin/dashboard + /admin/api/*   (admin-only, @admin_required)
# alerts_bp : /activity + /activity/api/mine    (per-user, @login_required)
app.register_blueprint(admin_bp)
app.register_blueprint(alerts_bp)


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


# --- INTENTIONAL VULNERABILITY (EASY): exposed debug endpoint, no auth required ---
# Documented in README as deliberate. Leaks system info for Red Team discovery.
@app.route('/api/debug')
def debug():
    app.logger.warning(f"Debug endpoint accessed by {request.remote_addr}")
    return jsonify({
        "python_version": sys.version,
        "platform": platform.platform(),
        "flask_env": "development",
        "app_secret_hint": "check .env file",  # intentionally leaky
        "flag": "DRIFTLOCK{d3bug_3ndp01nt_3xp0s3d}"
    })



# Define the valid flags and their respective levels
VALID_FLAGS = {
    "FLAG{34sy_f1l3_r34d}": "Easy",
    "FLAG{m3d1um_tot13_q3p0q3q}": "Medium",
    "FLAG{h4rd_c11_p1p3l1n3_m4st3r}": "Hard"
}

# Enhanced data tracking with timestamps
# Format: {username: {'Easy': datetime, 'Medium': datetime, 'Hard': datetime}}
USER_PROGRESS = {}

# Track all submissions with timestamps and usernames
# Format: [{'username': str, 'level': str, 'timestamp': datetime}, ...]
ALL_SUBMISSIONS = []


@app.route('/submit', methods=['GET', 'POST'])
def submit_flag():
    """Handle flag submission with timestamp tracking."""
    # Ensure user is logged in (using your existing auth mechanism)
    username = session.get('username', 'redteam_guest')
    
    if username not in USER_PROGRESS:
        USER_PROGRESS[username] = {}

    message = ""
    success = False

    if request.method == 'POST':
        submitted_flag = request.form.get('flag', '').strip()
        
        if submitted_flag in VALID_FLAGS:
            level = VALID_FLAGS[submitted_flag]
            
            # Check if user already solved this level
            if level not in USER_PROGRESS[username]:
                # Record timestamp for this submission
                submission_time = datetime.now()
                USER_PROGRESS[username][level] = submission_time
                
                # Add to global submissions list
                ALL_SUBMISSIONS.append({
                    'username': username,
                    'level': level,
                    'timestamp': submission_time
                })
                
                # TODO: Save USER_PROGRESS[username] and ALL_SUBMISSIONS to your persistent database here
                message = f"Correct! You solved the {level} challenge."
                success = True
                
                # Log the submission
                app.logger.info(f"Flag submitted by {username}: {level} at {submission_time}")
            else:
                existing_time = USER_PROGRESS[username][level].strftime('%Y-%m-%d %H:%M:%S')
                message = f"You already submitted the {level} flag on {existing_time}!"
        else:
            message = "Invalid flag. Try again!"

    return render_template(
        'submit.html', 
        message=message, 
        success=success, 
        user_solved=USER_PROGRESS[username]
    )


@app.route('/leaderboard')
def leaderboard():
    """Display all users who have submitted flags and their submission times."""
    # Sort submissions by timestamp (most recent first)
    sorted_submissions = sorted(ALL_SUBMISSIONS, key=lambda x: x['timestamp'], reverse=True)
    
    # Get unique users with their progress
    user_stats = {}
    for username in USER_PROGRESS:
        solved_count = len(USER_PROGRESS[username])
        # Get the most recent submission time for this user
        user_submissions = [s for s in ALL_SUBMISSIONS if s['username'] == username]
        last_submission = max([s['timestamp'] for s in user_submissions]) if user_submissions else None
        
        user_stats[username] = {
            'solved_count': solved_count,
            'last_submission': last_submission,
            'challenges': USER_PROGRESS[username]
        }
    
    # Sort users by number of challenges solved (descending), then by last submission time
    sorted_users = sorted(
        user_stats.items(),
        key=lambda x: (x[1]['solved_count'], x[1]['last_submission'] or datetime.min),
        reverse=True
    )
    
    return render_template(
        'leaderboard.html',
        user_stats=sorted_users,
        all_submissions=sorted_submissions
    )


@app.route('/api/submissions')
def api_submissions():
    """API endpoint to get all submissions as JSON."""
    # Convert datetime objects to strings for JSON serialization
    submissions = [
        {
            'username': s['username'],
            'level': s['level'],
            'timestamp': s['timestamp'].isoformat()
        }
        for s in sorted(ALL_SUBMISSIONS, key=lambda x: x['timestamp'], reverse=True)
    ]
    
    return jsonify({
        'total_submissions': len(ALL_SUBMISSIONS),
        'submissions': submissions
    })


@app.errorhandler(401)
def unauthorized(e):
    return jsonify({"error": "Unauthorized"}), 401


@app.errorhandler(404)
def not_found(e):
    app.logger.info(f"404 hit: {request.path} from {request.remote_addr}")
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(500)  # manage internal server errors
def internal_error(e):
    app.logger.error(f"Unhandled exception: {e}")
    return jsonify({"error": "Internal server error"}), 500


if __name__ == '__main__':
    # NOTE: debug=True is a development convenience. It exposes the Werkzeug
    # debugger (arbitrary code execution if reached) — this is NOT one of your
    # three intentional vulns, so turn it off for any graded/demo run to avoid
    # an accidental "security issue beyond the intentional one".
    app.run(host='0.0.0.0', port=4325, debug=True)