from database import db
from datetime import datetime

# 1. Users Table
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    mfa_enabled = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    totp_seed = db.relationship('TOTPSeed', backref='user', uselist=False, cascade="all, delete-orphan")
    reset_tokens = db.relationship('PasswordResetToken', backref='user', cascade="all, delete-orphan")
    logs = db.relationship('ActivityLog', backref='user')

# 2. TOTP Seeds Table (1:1 Relationship)
class TOTPSeed(db.Model):
    __tablename__ = 'totp_seeds'
    
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), primary_key=True)
    encrypted_seed = db.Column(db.String(255), nullable=False)
    backup_codes = db.Column(db.Text, nullable=False)  # Saved as a JSON string

# 3. Password Reset Tokens Table
class PasswordResetToken(db.Model):
    __tablename__ = 'password_reset_tokens'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    token_hash = db.Column(db.String(64), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)

# 4. Activity Logs Table (For Blue Team Incident Response)
class ActivityLog(db.Model):
    __tablename__ = 'activity_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    action = db.Column(db.String(100), nullable=False)        # e.g., 'LOGIN_FAILED', 'HONEYPOT_TRIGGER'
    status = db.Column(db.String(20), nullable=False)          # 'SUCCESS', 'FAILED', 'ALERT'
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.String(255), nullable=True)      # Fingerprint scanner tools
    request_path = db.Column(db.String(2045), nullable=True)   # Find what directories they are scanning
    session_id = db.Column(db.String(128), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)