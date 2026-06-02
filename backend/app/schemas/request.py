from pydantic import BaseModel, EmailStr, field_validator
from typing import Optional
import phonenumbers
from phonenumbers import NumberParseException


class ForgotPasswordRequest(BaseModel):
    email: EmailStr
    phone: Optional[str] = None

    @field_validator("phone")
    @classmethod
    def validate_phone(cls, phone: Optional[str]):
        if phone:
            try:
                parsed_number = phonenumbers.parse(phone, None)  # None = auto-detect country
                if not phonenumbers.is_valid_number(parsed_number):
                    raise ValueError("Invalid phone number for any country")
            except NumberParseException:
                raise ValueError("Invalid phone number format (use international format like +14155552671)")
        return phone


class VerifyOTPRequest(BaseModel):
    email: EmailStr
    otp: str

    @field_validator("otp")
    @classmethod
    def validate_otp(cls, otp: str):
        if not otp.isdigit() or len(otp) != 6:
            raise ValueError("OTP must be a 6-digit numeric code")
        return otp
