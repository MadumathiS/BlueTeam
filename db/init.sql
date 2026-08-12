CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    mfa_enabled BOOLEAN DEFAULT FALSE,
    role CHAR(1) NOT NULL DEFAULT 'U' CHECK (role IN ('A', 'U')),
    verification_code VARCHAR(255),   -- comma, not semicolon
    code_expires_at TIMESTAMP,        -- comma, not semicolon
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE totp_seeds (
    user_id INTEGER PRIMARY KEY REFERENCES users(id),
    encrypted_seed TEXT NOT NULL,
    backup_codes TEXT
);

CREATE TABLE password_reset_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN DEFAULT FALSE
);

CREATE TABLE activity_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    status VARCHAR(20) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    user_agent VARCHAR(255),
    request_path VARCHAR(2045),
    session_id VARCHAR(128),
    timestamp TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS honeypot_logs (
    id          BIGSERIAL PRIMARY KEY,
    "timestamp" TIMESTAMPTZ NOT NULL DEFAULT now(),
    severity    VARCHAR(20) NOT NULL DEFAULT 'CRITICAL',
    source_ip   VARCHAR(64),
    path        VARCHAR(255) NOT NULL,
    user_agent  TEXT,
    details     TEXT
);

CREATE INDEX IF NOT EXISTS idx_honeypot_logs_timestamp
    ON honeypot_logs ("timestamp" DESC);

-- CTF Flag Submission Tracking (Red Team progress monitoring)
CREATE TABLE ctf_submissions (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    level VARCHAR(50) NOT NULL,
    timestamp TIMESTAMP DEFAULT NOW(),
    ip_address INET,
    user_agent TEXT,
    UNIQUE(username, level)
);

CREATE INDEX idx_ctf_submissions_timestamp ON ctf_submissions(timestamp DESC);
CREATE INDEX idx_ctf_submissions_username ON ctf_submissions(username);
CREATE INDEX idx_ctf_submissions_level ON ctf_submissions(level);