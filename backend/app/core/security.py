# =========================================================
# app/core/security.py
# TRUST_EDGE ENTERPRISE SECURITY CORE
# =========================================================

import os
import secrets
import string
import hashlib
import hmac
import logging

from datetime import datetime, timedelta
from typing import Optional, Dict, Any

from jose import jwt, JWTError
from passlib.context import CryptContext


# =========================================================
# LOGGING
# =========================================================

logging.basicConfig(
    level=logging.INFO,
    format=(
        "[%(asctime)s] "
        "[%(levelname)s] "
        "[SECURITY] "
        "%(message)s"
    )
)

logger = logging.getLogger("security_core")

# =========================================================
# PASSWORD HASHING CONFIG
# =========================================================

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=14,
)

# =========================================================
# JWT CONFIG
# =========================================================

JWT_SECRET_KEY = os.getenv(
    "JWT_SECRET_KEY",
    "CHANGE_THIS_IN_PRODUCTION"
)

JWT_ALGORITHM = os.getenv(
    "JWT_ALGORITHM",
    "HS256"
)

ACCESS_TOKEN_EXPIRE_MINUTES = int(
    os.getenv(
        "ACCESS_TOKEN_EXPIRE_MINUTES",
        60
    )
)

REFRESH_TOKEN_EXPIRE_DAYS = int(
    os.getenv(
        "REFRESH_TOKEN_EXPIRE_DAYS",
        7
    )
)

ISSUER = os.getenv(
    "JWT_ISSUER",
    "TrustEdge"
)

AUDIENCE = os.getenv(
    "JWT_AUDIENCE",
    "TrustEdgeClients"
)

# =========================================================
# OTP GENERATION
# =========================================================

def generate_otp() -> str:
    """
    Generate secure 6-digit OTP
    """

    return str(
        secrets.randbelow(900000) + 100000
    )

# =========================================================
# SECURE TOKEN GENERATOR
# =========================================================

def create_secure_token(
    length: int = 64
) -> str:
    """
    Generate cryptographically secure token
    """

    alphabet = (
        string.ascii_letters
        + string.digits
    )

    return "".join(
        secrets.choice(alphabet)
        for _ in range(length)
    )

# =========================================================
# PASSWORD HASHING
# =========================================================

def get_password_hash(
    password: str
) -> str:
    """
    Securely hash password
    """

    return pwd_context.hash(password)

# =========================================================
# PASSWORD VERIFY
# =========================================================

def verify_password(
    plain_password: str,
    hashed_password: str
) -> bool:
    """
    Verify hashed password
    """

    try:

        return pwd_context.verify(
            plain_password,
            hashed_password
        )

    except Exception as e:

        logger.warning(
            f"Password verification failed: {e}"
        )

        return False

# =========================================================
# ACCESS TOKEN CREATION
# =========================================================

def create_access_token(
    data: Dict[str, Any],
    expires_delta: Optional[timedelta] = None
) -> str:
    """
    Create JWT access token
    """

    to_encode = data.copy()

    now = datetime.utcnow()

    expire = now + (
        expires_delta
        or timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES
        )
    )

    to_encode.update({
        "type": "access",
        "exp": expire,
        "iat": now,
        "nbf": now,
        "iss": ISSUER,
        "aud": AUDIENCE,
    })

    encoded_jwt = jwt.encode(
        to_encode,
        JWT_SECRET_KEY,
        algorithm=JWT_ALGORITHM
    )

    return encoded_jwt

# =========================================================
# REFRESH TOKEN CREATION
# =========================================================

def create_refresh_token(
    data: Dict[str, Any]
) -> str:
    """
    Create refresh token
    """

    to_encode = data.copy()

    now = datetime.utcnow()

    expire = now + timedelta(
        days=REFRESH_TOKEN_EXPIRE_DAYS
    )

    to_encode.update({
        "type": "refresh",
        "exp": expire,
        "iat": now,
        "nbf": now,
        "iss": ISSUER,
        "aud": AUDIENCE,
    })

    encoded_jwt = jwt.encode(
        to_encode,
        JWT_SECRET_KEY,
        algorithm=JWT_ALGORITHM
    )

    return encoded_jwt

# =========================================================
# TOKEN VALIDATION
# =========================================================

def verify_token(
    token: str
) -> Optional[Dict[str, Any]]:
    """
    Verify JWT token securely
    """

    try:

        payload = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
            audience=AUDIENCE,
            issuer=ISSUER,
        )

        return payload

    except JWTError as e:

        logger.warning(
            f"JWT validation failed: {e}"
        )

        return None

# =========================================================
# EXTRACT USER ID
# =========================================================

def extract_user_id(
    token: str
) -> Optional[str]:
    """
    Extract user ID from JWT
    """

    payload = verify_token(token)

    if not payload:
        return None

    return payload.get("sub")

# =========================================================
# ROLE CHECKER
# =========================================================

def has_role(
    token: str,
    required_role: str
) -> bool:
    """
    RBAC role checker
    """

    payload = verify_token(token)

    if not payload:
        return False

    user_role = payload.get("role")

    return user_role == required_role

# =========================================================
# API KEY GENERATOR
# =========================================================

def generate_api_key() -> str:
    """
    Generate enterprise API key
    """

    prefix = "te"

    random_part = create_secure_token(48)

    return f"{prefix}_{random_part}"

# =========================================================
# SESSION TOKEN
# =========================================================

def create_session_id() -> str:
    """
    Create secure session ID
    """

    return secrets.token_hex(32)

# =========================================================
# CSRF TOKEN
# =========================================================

def generate_csrf_token() -> str:
    """
    Generate CSRF token
    """

    return secrets.token_urlsafe(32)

# =========================================================
# DEVICE TOKEN
# =========================================================

def generate_device_token() -> str:
    """
    Generate device token
    """

    return secrets.token_hex(24)

# =========================================================
# HMAC SIGNATURE
# =========================================================

def create_hmac_signature(
    message: str,
    secret: str
) -> str:
    """
    Create HMAC SHA256 signature
    """

    return hmac.new(
        secret.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()

# =========================================================
# CONSTANT TIME COMPARISON
# =========================================================

def secure_compare(
    value1: str,
    value2: str
) -> bool:
    """
    Prevent timing attacks
    """

    return hmac.compare_digest(
        value1,
        value2
    )

# =========================================================
# TOKEN TYPE VALIDATION
# =========================================================

def validate_token_type(
    token: str,
    expected_type: str
) -> bool:
    """
    Validate token type
    """

    payload = verify_token(token)

    if not payload:
        return False

    return payload.get("type") == expected_type

# =========================================================
# STRONG PASSWORD GENERATOR
# =========================================================

def generate_strong_password(
    length: int = 18
) -> str:
    """
    Generate enterprise password
    """

    alphabet = (
        string.ascii_letters
        + string.digits
        + "!@#$%^&*()_+-="
    )

    return "".join(
        secrets.choice(alphabet)
        for _ in range(length)
    )

# =========================================================
# PASSWORD POLICY VALIDATION
# =========================================================

def validate_password_strength(
    password: str
) -> bool:
    """
    Enterprise password policy
    """

    if len(password) < 12:
        return False

    has_upper = any(c.isupper() for c in password)

    has_lower = any(c.islower() for c in password)

    has_digit = any(c.isdigit() for c in password)

    has_special = any(
        c in "!@#$%^&*()_+-="
        for c in password
    )

    return all([
        has_upper,
        has_lower,
        has_digit,
        has_special,
    ])

# =========================================================
# SECURITY HEADERS
# =========================================================

SECURITY_HEADERS = {

    "X-Frame-Options": "DENY",

    "X-Content-Type-Options": "nosniff",

    "Referrer-Policy": "no-referrer",

    "Permissions-Policy": (
        "camera=(), microphone=(), geolocation=()"
    ),

    "Strict-Transport-Security": (
        "max-age=31536000; includeSubDomains"
    ),

    "Content-Security-Policy": (
        "default-src 'self'"
    ),

    "Cross-Origin-Opener-Policy": (
        "same-origin"
    ),

    "Cross-Origin-Resource-Policy": (
        "same-origin"
    ),
}

# =========================================================
# HEALTH TEST
# =========================================================

if __name__ == "__main__":

    logger.info(
        "Testing enterprise security core..."
    )

    password = "TrustEdge@123"

    hashed = get_password_hash(password)

    print("\n========================")
    print("PASSWORD HASH")
    print("========================")
    print(hashed)

    print("\n========================")
    print("PASSWORD VERIFY")
    print("========================")
    print(
        verify_password(
            password,
            hashed
        )
    )

    token = create_access_token({
        "sub": "user_001",
        "role": "admin",
        "email": "admin@trustedge.ai"
    })

    print("\n========================")
    print("ACCESS TOKEN")
    print("========================")
    print(token)

    print("\n========================")
    print("TOKEN VERIFY")
    print("========================")
    print(
        verify_token(token)
    )

    print("\n========================")
    print("API KEY")
    print("========================")
    print(
        generate_api_key()
    )

    print("\n========================")
    print("STRONG PASSWORD")
    print("========================")
    print(
        generate_strong_password()
    )
