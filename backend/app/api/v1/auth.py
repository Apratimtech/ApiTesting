from fastapi import APIRouter, HTTPException, Request, status
from app.services.otp_service import send_otp
from app.schemas.request import ForgotPasswordRequest, VerifyOTPRequest
from app.core.rate_limit import limiter
from app.db.redis_conn import redis_client
import logging

logger = logging.getLogger(__name__)

# ❗ REMOVE prefix from here
router = APIRouter(tags=["auth"])


# ----------------------------------------------------
# 1️⃣ FORGOT PASSWORD → SEND OTP
# ----------------------------------------------------
@router.post("/forgot-password")
@limiter.limit("5/minute")
async def forgot_password(request: Request, data: ForgotPasswordRequest):

    email_key = data.email.lower()
    redis_rate_key = f"rate:forgot:{email_key}"

    attempts = redis_client.incr(redis_rate_key)
    if attempts == 1:
        redis_client.expire(redis_rate_key, 300)

    if attempts > 5:
        logger.warning(f"Too many OTP requests for {email_key}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many OTP requests. Try again later."
        )

    result = send_otp(data.email, data.phone)

    return {
        "success": True,
        "message": "OTP sent successfully",
        "email_sent": result["email_sent"],
        "sms_sent": result["sms_sent"],
        "telegram_sent": result.get("telegram_sent", False)
    }


# ----------------------------------------------------
# 2️⃣ VERIFY OTP
# ----------------------------------------------------
@router.post("/verify-otp")
@limiter.limit("10/minute")
async def verify_otp(request: Request, data: VerifyOTPRequest):

    email_key = data.email.lower()
    redis_otp_key = f"otp:{email_key}"
    redis_attempt_key = f"otp_attempts:{email_key}"

    stored_otp = redis_client.get(redis_otp_key)

    if not stored_otp:
        raise HTTPException(
            status_code=400,
            detail="OTP expired or invalid"
        )

    attempts = redis_client.incr(redis_attempt_key)
    if attempts == 1:
        redis_client.expire(redis_attempt_key, 600)

    if attempts > 6:
        redis_client.delete(redis_otp_key)
        raise HTTPException(
            status_code=429,
            detail="Too many attempts. OTP reset."
        )

    if stored_otp.decode() != data.otp:
        raise HTTPException(
            status_code=400,
            detail="Incorrect OTP"
        )

    redis_client.delete(redis_otp_key)
    redis_client.delete(redis_attempt_key)

    return {
        "success": True,
        "message": "OTP verified successfully"
    }
