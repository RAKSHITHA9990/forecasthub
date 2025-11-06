import pytest
# Import the functions you wrote from your source code
from src.managers.user_manager import hash_password, check_password, generate_auth_token

def test_password_hashing_and_verification_success():
    """Tests WTH-SR-002: Encrypt stored user credentials."""
    password = "MySecurePassword"
    hashed = hash_password(password)
    
    # 1. The hash must be different from the original password
    assert hashed != password
    
    # 2. Verification must succeed with the correct password
    assert check_password(password, hashed)

def test_password_verification_failure():
    """Tests that an incorrect password fails verification."""
    correct_password = "correct"
    wrong_password = "wrong"
    hashed = hash_password(correct_password)
    
    # Verification must fail with the wrong password
    assert not check_password(wrong_password, hashed)

def test_token_generation_and_structure():
    """Tests WTH-SR-003: Implement token-based authentication."""
    user_id = "PES2UG23CS134" # Example user ID
    token = generate_auth_token(user_id)
    
    # 1. Check that a token string is generated
    assert isinstance(token, str)
    
    # 2. Check that the token is not empty
    assert len(token) > 10