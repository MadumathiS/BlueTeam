# BlueTeam

never commit venv 

when installing in a new environment run these command
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

### Basic Repo Structure
blue-team-mfa-portal/
├── docker-compose.yml
├── .env                          # secrets (gitignored)
├── .gitignore
├── README.md
│
├── web/
│   ├── app.py                    # main Flask app, routes, session handling
│   ├── auth.py                   # login, password verification, session logic
│   ├── totp_utils.py             # HOTP/TOTP generation + verification (pyotp or custom HMAC)
│   ├── crypto_utils.py           # password hashing (bcrypt/argon2), TOTP seed encryption
│   ├── models.py                 # DB models (User, Session, etc.)
│   ├── decorators.py             # e.g. @login_required, @rate_limited
│   ├── requirements.txt
│   ├── Dockerfile
│   ├── templates/
│   │   ├── login.html
│   │   ├── mfa_setup.html
│   │   ├── mfa_verify.html
│   │   └── dashboard.html
│   ├── static/
│   │   ├── css/
│   │   │   └── output.css        # Tailwind (CDN or built)
│   │   └── js/
│   └── robots.txt                # discloses /backup_secrets/ — bait for honeypot
│
├── internal-api/
│   ├── api.py                    # e.g. /api/v1/users/setup-status (the intentional vuln lives here)
│   ├── requirements.txt
│   ├── Dockerfile
│
├── honeypot/
│   ├── decoy_app.py              # serves fake /backup_secrets/ content, logs access
│   ├── backup_secrets/
│   │   └── db_backup_2024.sql.bak   # fake, convincing decoy file
│   ├── requirements.txt
│   ├── Dockerfile
│
├── db/
│   ├── init.sql                  # users, sessions, honeypot_logs tables
│
├── secrets/
│   └── master_key.txt            # Docker secret, encrypts TOTP seeds at rest
│
├── logs/
│   ├── access.log
│   ├── honeypot.log               # separate high-priority alert log
│   └── captures/                  # .pcap files go here
│
└── reports/
    ├── 01-design-report.md
    ├── 02-hardening-report.md
    └── 03-incident-response.md
