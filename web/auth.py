from flask import current_app, redirect, render_template, url_for, session, request, jsonify
from crypto_utils import hash_password, encrypt_secret, verify_password, decrypt_secret
from models import db, User, TOTPSeed
import json
import pyotp
import re
import qrcode
import io
import base64


def is_valid_username(username):
    return bool(re.match(r'^[a-zA-Z0-9_]{3,20}$', username))


def is_valid_email(email):
    return bool(re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', email))


def register():
    if session.get('logged_in'):
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
        return redirect(url_for('home'))
    
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

    try:
        user = User.query.filter_by(username=username).first()

        if user is None:
            verify_password(password, DUMMY_HASH)
            current_app.logger.warning(f"Login failed (no such user) from {request.remote_addr}")
            return jsonify({"error": "Invalid username or password"}), 401

        if not verify_password(password, user.password_hash):
            current_app.logger.warning(f"Login failed for {username} from {request.remote_addr}")
            return jsonify({"error": "Invalid username or password"}), 401

        session.clear()

        if user.mfa_enabled:
            session['pending_mfa_user_id'] = user.id
            current_app.logger.info(f"Password OK, MFA pending: {username}")
            if request.is_json:
                return jsonify({"message": "MFA required", "mfa_required": True}), 200
            return redirect(url_for('verify_mfa'))

        session['logged_in'] = True
        session['user_id'] = user.id
        session['username'] = user.username
        current_app.logger.info(f"Login success: {username}")
        if request.is_json:
            return jsonify({"message": "Login successful"}), 200
        return redirect(url_for('home'))

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

    user.mfa_enabled = True
    db.session.commit()

    session.pop('pending_setup_user_id', None)
    current_app.logger.info(f"MFA setup confirmed for user_id={user.id}")

    return jsonify({"message": "MFA setup complete. You can now log in."}), 200

def generate_qr_base64(data: str) -> str:
    img = qrcode.make(data)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    return base64.b64encode(buf.getvalue()).decode()

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

        secret = decrypt_secret(user.totp_seed.encrypted_seed)
        totp = pyotp.TOTP(secret)

        if not totp.verify(code, valid_window=1):
            current_app.logger.warning(
                f"MFA verify failed for {user.username} from {request.remote_addr}")
            return jsonify({"error": "Invalid code"}), 401

        session.clear()
        session['logged_in'] = True
        session['user_id'] = user.id
        session['username'] = user.username
        current_app.logger.info(f"MFA verify success: {user.username}")
        if request.is_json:
            return jsonify({"message": "Login successful"}), 200
        return redirect(url_for('home'))

    except Exception as e:
        current_app.logger.exception("Error during MFA verify: %s", e)
        return jsonify({"error": "Internal server error"}), 500
