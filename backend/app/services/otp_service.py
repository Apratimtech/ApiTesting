import logging
import requests
from typing import Optional, Dict

from app.db.redis_conn import redis_client
from app.core.security import generate_otp
from app.core.email import send_otp_email
from app.core.config import settings
from app.services.telegram_service import send_telegram_otp

logger = logging.getLogger("otp_service")


def send_otp(email: str, phone: Optional[str] = None) -> Dict[str, bool]:
    """
    Generates OTP, stores in Redis, and sends via Email/SMS/Telegram
    """

    # -----------------------------
    # 1) Generate OTP
    # -----------------------------
    otp = generate_otp()
    redis_key = f"otp:{email.lower()}"

    # -----------------------------
    # 2) Store in Redis
    # -----------------------------
    try:
        redis_client.setex(redis_key, 600, otp)
    except Exception as e:
        logger.critical(f"[REDIS ERROR]: {e}")
        return {"email_sent": False, "sms_sent": False, "telegram_sent": False}

    # -----------------------------
    # 3) Email
    # -----------------------------
    email_sent = False
    try:
        email_sent = send_otp_email(email, otp)
    except Exception as e:
        logger.error(f"[EMAIL ERROR]: {e}")

    # -----------------------------
    # 4) SMS
    # -----------------------------
    sms_sent = False
    if phone:
        try:
            url = "https://api.msg91.com/api/v5/otp"

            payload = {
                "template_id": settings.MSG91_TEMPLATE_ID,
                "mobile": phone.replace("+", "").strip(),
                "otp": otp,
                "sender": settings.MSG91_SENDER_ID,
            }

            headers = {
                "authkey": settings.MSG91_AUTH_KEY,
                "Content-Type": "application/json",
            }

            response = requests.post(url, json=payload, headers=headers, timeout=8)

            if response.status_code == 200:
                sms_sent = True
            else:
                logger.error(f"[MSG91 ERROR]: {response.text}")

        except Exception as e:
            logger.error(f"[SMS ERROR]: {e}")

    # -----------------------------
    # 5) Telegram
    # -----------------------------
    telegram_sent = False
    try:
        if settings.TELEGRAM_CHAT_ID:
            send_telegram_otp(settings.TELEGRAM_CHAT_ID, otp)
            telegram_sent = True
    except Exception as e:
        logger.error(f"[TELEGRAM ERROR]: {e}")

    # -----------------------------
    return {
        "email_sent": email_sent,
        "sms_sent": sms_sent,
        "telegram_sent": telegram_sent,
    }
