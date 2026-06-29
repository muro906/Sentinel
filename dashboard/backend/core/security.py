"""Security utilities for authentication and authorization.

Provides password hashing, JWT token creation/validation, and
cryptographic helper functions.
"""

from datetime import datetime, timedelta, timezone

import bcrypt
from jose import jwt

from core.config import settings

# bcrypt salt rounds (higher = more secure but slower)
BCRYPT_ROUNDS = 12

# JWT signing algorithm
ALGORITHM = "HS256"


def hash_password(password: str) -> str:
    """Hash a plaintext password using bcrypt.
    
    Args:
        password: The plaintext password to hash.
        
    Returns:
        The hashed password string.
    """
    # bcrypt has 72 byte limit on passwords
    password_bytes = password[:72].encode('utf-8')
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plaintext password against a hash.
    
    Args:
        plain: The plaintext password to verify.
        hashed: The stored password hash.
        
    Returns:
        True if the password matches, False otherwise.
    """
    plain_bytes = plain[:72].encode('utf-8')
    hashed_bytes = hashed.encode('utf-8')
    return bcrypt.checkpw(plain_bytes, hashed_bytes)


def create_access_token(subject: str, role: str) -> str:
    """Create a short-lived access token for API authentication.
    
    Expires after 15 minutes. Contains user identity and role.
    
    Args:
        subject: The username or user identifier.
        role: The user's role (e.g., 'analyst', 'admin').
        
    Returns:
        Encoded JWT access token string.
    """
    exp = datetime.now(timezone.utc) + timedelta(hours=8)
    return jwt.encode(
        {"sub": subject, "role": role, "exp": exp, "type": "access"},
        settings.JWT_SECRET_KEY,
        algorithm=ALGORITHM
    )


def create_refresh_token(subject: str, role: str) -> str:
    """Create a long-lived refresh token for token renewal.
    
    Expires after 8 hours. Used to obtain new access tokens.
    
    Args:
        subject: The username or user identifier.
        role: The user's role.
        
    Returns:
        Encoded JWT refresh token string.
    """
    exp = datetime.now(timezone.utc) + timedelta(hours=8)
    return jwt.encode(
        {"sub": subject, "role": role, "exp": exp, "type": "refresh"},
        settings.JWT_SECRET_KEY,
        algorithm=ALGORITHM
    )


def decode_token(token: str) -> dict:
    """Decode and validate a JWT token.
    
    Args:
        token: The JWT token string to decode.
        
    Returns:
        The decoded token payload as a dictionary.
        
    Raises:
        jose.JWTError: If the token is invalid or expired.
    """
    return jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[ALGORITHM])