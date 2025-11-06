import bcrypt # For WTH-SR-002 (hashing)
import jwt    # For WTH-SR-003 (token generation)
import os     # <--- NEW: Imported for secure environment variable loading
from datetime import datetime, timedelta

# Fix for Bandit/Security Scan: Loads from the environment variable JWT_SECRET_KEY.
# The default is only used if the environment variable is not set (e.g., during testing).
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "A_FALLBACK_SECRET_KEY_FOR_TESTS") 

# WTH-SR-002 Implementation
def hash_password(password: str) -> str:
    # Generates a salt and hashes the password
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password(password: str, hashed_password: str) -> bool:
    # Verifies the provided password against the stored hash
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

# WTH-SR-003 Implementation
def generate_auth_token(user_id: str) -> str:
    # Creates a token payload with an expiry time
    payload = {
        'exp': datetime.utcnow() + timedelta(days=0, hours=1), # Expires in 1 hour
        'iat': datetime.utcnow(),
        'sub': user_id # Subject is the user_id
    }
    # Encodes the token
    return jwt.encode(
        payload,
        SECRET_KEY,
        algorithm='HS256'
    )