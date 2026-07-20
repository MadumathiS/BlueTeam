# web/mfa.py
from flask import Blueprint, render_template, jsonify, session, redirect, url_for
from models import User
from crypto_utils import decrypt_secret
from decorators import login_required
import time
import pyotp

totp_bp = Blueprint('totp', __name__)

@totp_bp.route('/authenticator')
@login_required
def authenticator():
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    if not user:
        session.clear()
        return redirect(url_for('login'))
    return render_template('mfa.html', current_user=user)


@totp_bp.route('/api/current-code')
@login_required
def current_code():
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    if not user:
        session.clear()
        return jsonify({"error": "Not authenticated"}), 401
    if not user.totp_seed:
        return jsonify({"error": "No TOTP configured"}), 404

    secret = decrypt_secret(user.totp_seed.encrypted_seed)
    totp = pyotp.TOTP(secret)

    return jsonify({
        "code": totp.now(),
        "time_remaining": totp.interval - (int(time.time()) % totp.interval)
    })
