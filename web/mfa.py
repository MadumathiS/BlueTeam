# web/totp_routes.py
from flask import Blueprint, render_template, jsonify, session, redirect, url_for
from models import User, TOTPSeed
from crypto_utils import decrypt_secret
import time
import pyotp

totp_bp = Blueprint('totp', __name__)

@totp_bp.route('/dashboard')
def dashboard():
    user_id = 1 #session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))  # adjust to your actual login route name
    user = User.query.get(user_id)
    if not user:
        return redirect(url_for('login'))  # adjust to your actual login route name
    return render_template('mfa.html',current_user=user)  # replace with actual user retrieval logic

@totp_bp.route('/api/current-code')
def current_code():
    user_id = 1 #session.get('user_id')
    if not user_id:
        return jsonify({"error": "Not authenticated"}), 401

    user = User.query.get(user_id)
    if not user or not user.totp_seed:
        return jsonify({"error": "No TOTP configured"}), 404

    secret = decrypt_secret(user.totp_seed.encrypted_seed)
    totp = pyotp.TOTP(secret)

    return jsonify({
        "code": totp.now(),
        "time_remaining": totp.interval - (int(time.time()) % totp.interval)
    })