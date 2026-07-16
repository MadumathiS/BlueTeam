import bcrypt
from cryptography.fernet import Fernet
import os

# In production this key comes from secrets/master_key.txt (Docker secret)
MASTER_KEY = os.getenv("MASTER_KEY", Fernet.generate_key())
if not MASTER_KEY:
    raise RuntimeError(
        "MASTER_KEY environment variable is not set. "
        "Refusing to start with an auto-generated key, since TOTP seeds "
        "encrypted with a throwaway key become permanently undecryptable "
        "on restart. Set MASTER_KEY in your .env file."
    )
fernet = Fernet(MASTER_KEY if isinstance(MASTER_KEY, bytes) else MASTER_KEY.encode())

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())

def encrypt_secret(secret: str) -> str:
    return fernet.encrypt(secret.encode()).decode()

def decrypt_secret(token: str) -> str:
    return fernet.decrypt(token.encode()).decode()