import bcrypt # For WTH-SR-002 (hashing)
import jwt    # For WTH-SR-003 (token generation)
from datetime import datetime, timedelta

# Note: In a real project, SECRET_KEY should be loaded from a .env file (which you ignored in .gitignore)
SECRET_KEY = "DEV_SECRET_KEY" 

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