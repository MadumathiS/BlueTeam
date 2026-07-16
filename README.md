# BlueTeam

never commit venv 

when installing in a new environment run these command
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

### Basic Repo Structure
```
## Repository Structure

### Current (as built)

blue-team-mfa-portal/
├── docker-compose.yml            # web + db + redis; mounts ./logs:/app/logs
├── .env                          # secrets (gitignored)
├── .gitignore
├── README.md
│
├── web/
│   ├── app.py                    # Flask app, routes, logging, rate limiting;
│   │                             #   /api/debug = intentional vuln
│   ├── auth.py                   # registration / login / password verification
│   ├── crypto_utils.py           # password hashing + TOTP seed encryption
│   ├── mfa.py                    # TOTP blueprint (totp_bp): MFA setup + verify
│   ├── models.py                 # DB models (User, etc.)
│   ├── honeypot.py               # honeypot blueprint: robots.txt bait +
│   │                             #   /backup_secrets/ trap, embedded decoy
│   ├── robots.txt                # discloses /backup_secrets/ — bait
│   ├── requirements.txt
│   ├── Dockerfile
│   ├── templates/
│   └── static/
│
├── db/
│   └── init.sql                  # users, totp_seeds, password_reset_tokens,
│                                 #   activity_logs, honeypot_logs
├── secrets/
│   └── master_key.txt
├── logs/
│   ├── access.log
│   ├── honeypot.log
│   └── captures/
└── reports/
    ├── 01-design-report.md
    ├── 02-hardening-report.md
    └── 03-incident-response.md


### Planned / target architecture

Items below are part of the intended design but not yet built:

- internal-api/          # separate service; will host /api/v1/users/setup-status
                         #   (moves the intentional vuln out of web/app.py)
- web/decorators.py      # @login_required, @rate_limited helpers
```