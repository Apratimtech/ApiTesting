import requests
from app.core.config import settings

def send_telegram_otp(chat_id: str, otp: str) -> bool:
    """
    Sends OTP to a Telegram user.
    """
    url = f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/sendMessage"

    message = (
        f"🔐 *Trust_Edge Verification*\n\n"
        f"Your OTP is: *{otp}*\n"
        f"This OTP expires in 10 minutes.\n"
        f"Do NOT share this OTP with anyone."
    )

    payload = {
        "chat_id": chat_id,
        "text": message,
        "parse_mode": "Markdown"
    }

    try:
        response = requests.post(url, json=payload, timeout=5)
        return response.status_code == 200
    except Exception as e:
        print(f"Telegram OTP error: {e}")
        return False
