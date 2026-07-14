import bcrypt
from cryptography.fernet import Fernet
import os

# In production this key comes from secrets/master_key.txt (Docker secret)
MASTER_KEY = os.getenv("MASTER_KEY", Fernet.generate_key())
fernet = Fernet(MASTER_KEY if isinstance(MASTER_KEY, bytes) else MASTER_KEY.encode())

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())

def encrypt_secret(secret: str) -> str:
    return fernet.encrypt(secret.encode()).decode()

def decrypt_secret(token: str) -> str:
    return fernet.decrypt(token.encode()).decode()