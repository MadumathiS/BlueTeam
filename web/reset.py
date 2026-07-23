from flask import current_app, render_template, request, jsonify
from crypto_utils import hash_password
from models import db, User, PasswordResetToken
from datetime import datetime, timedelta
import secrets
import hashlib
import smtplib
from email.mime.text import MIMEText
import os

TOKEN_EXPIRY_MINUTES = 15

SMTP_HOST = os.getenv('SMTP_HOST', 'mailpit')
SMTP_PORT = int(os.getenv('SMTP_PORT', 1025))
APP_URL = os.getenv('APP_URL', 'http://localhost:4325')


def _hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


def _send_reset_email(to_email, username, reset_url):
    full_url = f"{APP_URL}{reset_url}"
    body = (
        f"Hi {username},\n\n"
        f"A password reset was requested for your DriftLock account.\n\n"
        f"Click this link to reset your password:\n"
        f"{full_url}\n\n"
        f"This link expires in {TOKEN_EXPIRY_MINUTES} minutes.\n\n"
        f"If you did not request this, ignore this email.\n\n"
        f"— DriftLock Security"
    )
    msg = MIMEText(body)
    msg['Subject'] = 'DriftLock - Password Reset'
    msg['From'] = 'security@driftlock.local'
    msg['To'] = to_email

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.send_message(msg)
        current_app.logger.info(f"Reset email sent to {to_email}")
    except Exception as e:
        current_app.logger.error(f"Failed to send reset email: {e}")


def request_reset():
    if request.method == 'GET':
        return render_template('reset_request.html')

    if request.is_json:
        data = request.get_json(silent=True) or {}
    else:
        data = request.form.to_dict(flat=True)

    email = str(data.get('email', '')).strip().lower()
    if not email:
        return jsonify({"error": "Email is required"}), 400

    user = User.query.filter_by(email=email).first()

    if user:
        PasswordResetToken.query.filter_by(user_id=user.id, used=False).delete()

        raw_token = secrets.token_urlsafe(32)
        reset_token = PasswordResetToken(
            user_id=user.id,
            token_hash=_hash_token(raw_token),
            expires_at=datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRY_MINUTES),
            used=False
        )
        db.session.add(reset_token)
        db.session.commit()

        reset_url = f"/reset-password/{raw_token}"
        current_app.logger.info(
            f"PASSWORD_RESET_REQUESTED | user={user.username}"
        )
        _send_reset_email(user.email, user.username, reset_url)
    else:
        current_app.logger.info(
            f"PASSWORD_RESET_REQUESTED | email={email} | no_matching_account"
        )

    return jsonify({"message": "If an account with that email exists, a reset link has been sent."}), 200


def reset_password(token):
    token_hash = _hash_token(token)
    reset_record = PasswordResetToken.query.filter_by(
        token_hash=token_hash, used=False
    ).first()

    if not reset_record or reset_record.expires_at < datetime.utcnow():
        return jsonify({"error": "Invalid or expired reset link"}), 400

    if request.method == 'GET':
        return render_template('reset_form.html', token=token)

    if request.is_json:
        data = request.get_json(silent=True) or {}
    else:
        data = request.form.to_dict(flat=True)

    password = data.get('password', '')
    confirm = data.get('confirm_password', '')

    if not isinstance(password, str) or len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    if password != confirm:
        return jsonify({"error": "Passwords do not match"}), 400

    user = User.query.get(reset_record.user_id)
    if not user:
        return jsonify({"error": "Invalid token"}), 400

    user.password_hash = hash_password(password)
    reset_record.used = True
    db.session.commit()

    current_app.logger.info(f"PASSWORD_RESET_COMPLETE | user={user.username}")
    return jsonify({"message": "Password reset successful. You can now log in."}), 200
