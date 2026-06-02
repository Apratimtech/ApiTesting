import resend
from typing import Optional
from app.core.config import settings

# Set API key
resend.api_key = settings.RESEND_API_KEY


def send_otp_email(email: str, otp: str) -> bool:
    """
    Sends OTP email using Resend API.
    Returns True if email sent successfully, False on failure.
    """

    html_content = f"""
        <div style="font-family: Arial, sans-serif; padding: 16px;">
            <h2 style="color:#4F46E5;">Trust Edge Security Verification</h2>
            <p>Your One-Time Password (OTP) is:</p>
            <h1 style="color:#111; letter-spacing: 3px;">{otp}</h1>
            <p>This OTP will expire in <strong>10 minutes</strong>.</p>
            <p style="color:#DC2626;"><strong>Do NOT share this OTP with anyone.</strong></p>
            <hr style="margin-top: 20px;">
            <p style="font-size:12px; color:#6B7280;">This is an automated message from Trust Edge.</p>
        </div>
    """

    try:
        response = resend.Emails.send({
            "from": "Lakshya from TrustEdge <onboarding@resend.dev>",
            "to": [email],
            "subject": "Your OTP for Password Reset",
            "html": html_content,
        })

        print("Resend Response:", response)
        return True

    except Exception as e:
        print(f"Email sending error: {e}")
        return False
