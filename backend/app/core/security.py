import secrets
import string
from passlib.context import CryptContext

# Password hashing setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ---------------------------
#  OTP GENERATION
# ---------------------------
def generate_otp():
    """
    Generate a secure 6-digit OTP
    """
    return str(secrets.randbelow(900000) + 100000)


# ---------------------------
#  TOKEN CREATION
# ---------------------------
def create_secure_token(length=32):
    """
    Generate a cryptographically-secure token
    """
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


# ---------------------------
#  PASSWORD UTILITIES
# ---------------------------
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)
