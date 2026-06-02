from fastapi import APIRouter, HTTPException, Request, status
from app.schemas.request import ForgotPasswordRequest, VerifyOTPRequest
from app.services.otp_service import send_otp
from app.core.rate_limit import limiter
from app.db.redis_conn import redis_client
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/auth", tags=["auth"])


# ----------------------------------------------------
# 1️⃣ FORGOT PASSWORD → SEND OTP
# ----------------------------------------------------
@router.post("/forgot-password")
@limiter.limit("5/minute")   # global per-IP rate limit
async def forgot_password(request: Request, data: ForgotPasswordRequest):

    email_key = data.email.lower()
    redis_rate_key = f"rate:forgot:{email_key}"

    # Per-email throttling — prevents requesting OTP repeatedly on same email
    attempts = redis_client.incr(redis_rate_key)
    if attempts == 1:
        redis_client.expire(redis_rate_key, 300)  # 5 minutes

    if attempts > 5:
        logger.warning(f"Too many OTP requests for {email_key}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many OTP requests. Try again after 5 minutes."
        )

    # Call OTP sending service
    result = send_otp(data.email, data.phone)

    return {
        "success": True,
        "message": (
            "OTP sent successfully to your email"
            + (" and phone" if data.phone else "")
        ),
        "email_sent": result["email_sent"],
        "sms_sent": result["sms_sent"]
    }


# ----------------------------------------------------
# 2️⃣ VERIFY OTP
# ----------------------------------------------------
@router.post("/verify-otp")
@limiter.limit("10/minute")  # global per-IP limit
async def verify_otp(request: Request, data: VerifyOTPRequest):

    email_key = data.email.lower()
    redis_otp_key = f"otp:{email_key}"
    redis_attempt_key = f"otp_attempts:{email_key}"

    stored_otp = redis_client.get(redis_otp_key)

    if not stored_otp:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OTP has expired or this request is invalid"
        )

    # ------------------------------
    # Brute force protection: 6 try limit
    # ------------------------------
    attempts = redis_client.incr(redis_attempt_key)
    if attempts == 1:
        redis_client.expire(redis_attempt_key, 600)  # 10 mins

    if attempts > 6:
        logger.warning(f"OTP brute force blocked for {email_key}")
        redis_client.delete(redis_otp_key)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many incorrect attempts. OTP has been reset. Request a new one."
        )

    # ------------------------------
    # Compare OTP
    # ------------------------------
    if stored_otp.decode() != data.otp:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect OTP"
        )

    # ------------------------------
    # Successful verification → cleanup
    # ------------------------------
    redis_client.delete(redis_otp_key)
    redis_client.delete(redis_attempt_key)

    return {
        "success": True,
        "message": "OTP verified successfully"
    }
