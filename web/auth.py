from flask import current_app, redirect, render_template, url_for, session, request, jsonify
from crypto_utils import hash_password, encrypt_secret, verify_password, decrypt_secret
from models import db, User, TOTPSeed, PasswordResetToken
from sqlalchemy import or_
from detections import record_totp_use
from datetime import datetime, timedelta
import secrets
import json
import pyotp
import re
from utils import generate_qr_base64
import os
import redis

_redis = redis.Redis(
    host=os.getenv('REDIS_HOST', 'redis'),
    port=int(os.getenv('REDIS_PORT', 6379)),
    decode_responses=True
)
MAX_LOGIN_ATTEMPTS = 3
LOCKOUT_SECONDS = 60
CODE_TTL_MINUTES = 5

import smtplib
from email.mime.text import MIMEText

SMTP_HOST = os.getenv('SMTP_HOST', 'mailpit')
SMTP_PORT = int(os.getenv('SMTP_PORT', 1025))

def _send_mfa_code(to_email, username, code):
    body = (
        f"Hi {username},\n\n"
        f"Your DriftLock verification code is: {code}\n\n"
        f"This code expires in 5 minutes.\n\n"
        f"If you did not attempt to log in, secure your account immediately.\n\n"
        f"— DriftLock Security"
    )
    msg = MIMEText(body)
    msg['Subject'] = 'DriftLock - Your Login Verification Code'
    msg['From'] = 'security@driftlock.local'
    msg['To'] = to_email
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.send_message(msg)
        current_app.logger.info(f"MFA code sent to {to_email}")
    except Exception as e:
        current_app.logger.error(f"Failed to send MFA code: {e}")

def is_valid_username(username):
    return bool(re.match(r'^[a-zA-Z0-9_]{3,20}$', username))


def is_valid_email(email):
    return bool(re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', email))

def generate_numeric_code(length=6):
    return ''.join(secrets.choice('0123456789') for _ in range(length))

def _issue_login_code(user):
    code = generate_numeric_code()
    user.verification_code = hash_password(code)
    user.code_expires_at = datetime.utcnow() + timedelta(minutes=CODE_TTL_MINUTES)
    db.session.commit()
    _send_mfa_code(user.email, user.username, code)
    return code

def _verify_login_code(user, submitted_code):
    if not user.verification_code or not user.code_expires_at:
        return False
    if datetime.utcnow() > user.code_expires_at:
        return False
    if not verify_password(submitted_code, user.verification_code):
        return False
    # single-use - clear immediately
    user.verification_code = None
    user.code_expires_at = None
    db.session.commit()
    return True

def register():
    resume_user_id = session.get('pending_setup_user_id') if not session.get('logged_in') else None
    if session.get('logged_in') or resume_user_id:
        user_id = session.get('user_id') or resume_user_id
        user = User.query.get(user_id)
        if not user:
            session.clear()
            return redirect(url_for('login'))

        if user.mfa_enabled:
            # Fully set up already - nothing to do here
            return redirect(url_for('totp.authenticator'))

        # Logged in, but MFA setup was never completed - show the QR step
        # directly instead of the registration form
        if user.totp_seed:
            secret = decrypt_secret(user.totp_seed.encrypted_seed)
            provisioning_uri = pyotp.totp.TOTP(secret).provisioning_uri(
                name=user.username, issuer_name="DriftlockPortal"
            )
            qr_base64 = generate_qr_base64(provisioning_uri)
            backup_codes = json.loads(user.totp_seed.backup_codes)
            session['pending_setup_user_id'] = user.id

            return render_template(
                'register.html',
                mfa_setup_only=True,
                qr_code=qr_base64,
                backup_codes=backup_codes
            )

        # Edge case: logged in, no seed at all - shouldn't normally happen
        return redirect(url_for('home'))

    if request.method == 'GET':
        return render_template('register.html')

    current_app.logger.info('Register endpoint hit')

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

    if not email:
        return jsonify({"error": "Email is required"}), 400
    if not is_valid_email(email):
        return jsonify({"error": "Invalid email format"}), 400
    if not is_valid_username(username):
        return jsonify({"error": "Invalid username format"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    if password != confirm_password:
        return jsonify({"error": "Passwords do not match"}), 400

    try:
        if User.query.filter_by(username=username).first():
            current_app.logger.warning(f"Duplicate registration attempt: {username} from {request.remote_addr}")
            return jsonify({"error": "Username already exists"}), 409
        if User.query.filter_by(email=email).first():
            current_app.logger.warning(f"Duplicate email registration attempt: {email} from {request.remote_addr}")
            return jsonify({"error": "Email already exists"}), 409

        new_user = User(
            username=username,
            email=email,
            password_hash=hash_password(password),
            mfa_enabled=False
        )
        db.session.add(new_user)
        db.session.flush()

        totp_secret = pyotp.random_base32()
        backup_codes = [pyotp.random_base32()[:8] for _ in range(5)]

        new_seed = TOTPSeed(
            user_id=new_user.id,
            encrypted_seed=encrypt_secret(totp_secret),
            backup_codes=json.dumps(backup_codes)
        )
        db.session.add(new_seed)
        db.session.commit()

        current_app.logger.info(f"New user registered: {username}")
        session['pending_setup_user_id'] = new_user.id
        provisioning_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
            name=username, issuer_name="DriftlockPortal"
        )
        qr_base64 = generate_qr_base64(provisioning_uri) 
        return jsonify({
            "message": "User registered successfully",
            "provisioning_uri": provisioning_uri,
            "backup_codes": backup_codes,
            "qr_code": qr_base64
        }), 201
    except Exception as e:
        current_app.logger.exception("Error during registration: %s", e)
        print(e)
        print(f"Error during registration: {e}", flush=True)
        db.session.rollback()
        return jsonify({"error": "Internal server error", "detail": str(e)}), 500

    
DUMMY_HASH = hash_password('dummy_password_for_timing')


def login():
    if session.get('logged_in'):
        user = User.query.get(session.get('user_id'))
        if not user:
            session.clear()
            return redirect(url_for('login'))

        if not user.mfa_enabled:
            # Logged in, but never completed MFA setup - send them to finish it
            return redirect(url_for('register'))

        return redirect(url_for('totp.authenticator'))

    if session.get('pending_mfa_user_id'):
        return redirect(url_for('verify_mfa'))

    if request.method == 'GET':
        return render_template('login.html')

    current_app.logger.info('Login endpoint hit')

    if request.is_json:
        data = request.get_json(silent=True) or {}
    else:
        data = request.form.to_dict(flat=True)

    if not data or not isinstance(data, dict):
        return jsonify({"error": "Invalid or missing request body"}), 400

    username = str(data.get('username', '')).strip()
    password = data.get('password', '')
    if not isinstance(password, str):
        password = ''

    attempts_key = f"failed_login:{username.lower()}"

    try:
        current_attempts = int(_redis.get(attempts_key) or 0)
        if current_attempts >= MAX_LOGIN_ATTEMPTS:
            current_app.logger.warning(
                f"Locked-out login attempt for {username} from {request.remote_addr}"
            )
            return jsonify({
                "error": "Account temporarily locked",
                "locked": True
            }), 401

        user = User.query.filter(
            or_(User.username == username, User.email == username.lower())
        ).first()

        if user is None:
            verify_password(password, DUMMY_HASH)
            current_app.logger.warning(
                f"Login failed (no such user) from {request.remote_addr}"
            )
            attempts = _redis.incr(attempts_key)
            if attempts == 1:
                _redis.expire(attempts_key, LOCKOUT_SECONDS)
            remaining = MAX_LOGIN_ATTEMPTS - attempts
            if attempts >= MAX_LOGIN_ATTEMPTS:
                return jsonify({"error": "Account temporarily locked", "locked": True}), 401
            return jsonify({
                "error": "Invalid username or password",
                "attempts_remaining": remaining
            }), 401

        if not verify_password(password, user.password_hash):
            current_app.logger.warning(
                f"Login failed for {username} from {request.remote_addr}"
            )
            attempts = _redis.incr(attempts_key)
            if attempts == 1:
                _redis.expire(attempts_key, LOCKOUT_SECONDS)
            remaining = MAX_LOGIN_ATTEMPTS - attempts
            if attempts >= MAX_LOGIN_ATTEMPTS:
                return jsonify({"error": "Account temporarily locked", "locked": True}), 401
            return jsonify({
                "error": "Invalid username or password",
                "attempts_remaining": remaining
            }), 401

        _redis.delete(attempts_key)

        if not user.mfa_enabled:
            session.clear()
            if user.totp_seed:
                secret = decrypt_secret(user.totp_seed.encrypted_seed)
                provisioning_uri = pyotp.totp.TOTP(secret).provisioning_uri(
                    name=user.username, issuer_name="DriftlockPortal"
                )
                qr_base64 = generate_qr_base64(provisioning_uri)
                backup_codes = json.loads(user.totp_seed.backup_codes)
                session['pending_setup_user_id'] = user.id
                current_app.logger.info(f"Login blocked - resuming MFA setup: {username}")
                if request.is_json:
                    return jsonify({
                        "error": "MFA setup incomplete",
                        "resume_setup": True,
                        "qr_code": qr_base64,
                        "backup_codes": backup_codes,
                        "redirect": url_for('register'),
                        "mfa_required": True
                    }), 403
            return redirect(url_for('register'))

        if user.mfa_enabled:
            session['pending_mfa_user_id'] = user.id
            _issue_login_code(user)
            current_app.logger.info(f"Password OK, login code emailed: {username}")
            if request.is_json:
                return jsonify({"message": "Verification code sent", "mfa_required": True, "redirect": url_for('verify_mfa')}), 200
            return redirect(url_for('verify_mfa'))

        session['logged_in'] = True
        session['user_id'] = user.id
        session['username'] = user.username
        current_app.logger.info(f"Login success: {username}")
        if request.is_json:
            return jsonify({"message": "Login successful"}), 200
        return redirect(url_for('totp.authenticator'))

    except Exception as e:
        current_app.logger.exception("Error during login: %s", e)
        return jsonify({"error": "Internal server error"}), 500


def logout():
    session.clear()
    return redirect(url_for('home'))


def confirm_mfa_setup():
    user_id = session.get('pending_setup_user_id')
    if not user_id:
        return jsonify({"error": "No pending MFA setup"}), 400

    data = request.get_json(silent=True) or {}
    code = str(data.get('code', '')).strip()

    user = User.query.get(user_id)
    if not user or not user.totp_seed:
        return jsonify({"error": "Invalid session"}), 400

    secret = decrypt_secret(user.totp_seed.encrypted_seed)
    totp = pyotp.TOTP(secret)

    if not totp.verify(code, valid_window=1):
        return jsonify({"error": "Invalid code, try again"}), 401

    # Record detection event on setup verification
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    record_totp_use(user.id, client_ip, context="mfa_setup")

    user.mfa_enabled = True
    db.session.commit()

    session.pop('pending_setup_user_id', None)
    current_app.logger.info(f"MFA setup confirmed for user_id={user.id}")

    return jsonify({"message": "MFA setup complete. You can now log in."}), 200


def resend_mfa():
    user_id = session.get('pending_mfa_user_id')
    if not user_id:
        return jsonify({"error": "No pending MFA session"}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "Invalid session"}), 400

    _issue_login_code(user)
    current_app.logger.info(f"MFA code resent to {user.email}")
    return jsonify({"message": "A new code has been sent to your email."}), 200


def verify_mfa():
    user_id = session.get('pending_mfa_user_id')
    if not user_id:
        return redirect(url_for('login'))

    if request.method == 'GET':
        return render_template('mfa_verify.html')

    if request.is_json:
        data = request.get_json(silent=True) or {}
    else:
        data = request.form.to_dict(flat=True)

    code = str(data.get('code', '')).strip()

    try:
        user = User.query.get(user_id)
        if not user or not user.totp_seed:
            session.clear()
            return jsonify({"error": "Invalid session"}), 400

        if not _verify_login_code(user, code):
            current_app.logger.warning(f"MFA verify failed for {user.username} from {request.remote_addr}")
            return jsonify({"error": "Invalid or expired code"}), 401
        # Single-use is enforced in _verify_login_code (emailed code invalidated after one use).
        # record_totp_use is a DETECTION signal only here (non-blocking).
        client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        record_totp_use(user.id, client_ip, context="login")
        session.clear()
        session['logged_in'] = True
        session['user_id'] = user.id
        session['username'] = user.username
        current_app.logger.info(f"MFA verify success: {user.username}")
        if request.is_json:
            return jsonify({"message": "Login successful"}), 200
        return redirect(url_for('totp.authenticator'))

    except Exception as e:
        current_app.logger.exception("Error during MFA verify: %s", e)
        return jsonify({"error": "Internal server error"}), 500