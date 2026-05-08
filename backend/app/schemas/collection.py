from pydantic import BaseModel, Field, HttpUrl, validator
from typing import Optional, Dict, Any
from enum import Enum
from datetime import datetime


# -----------------------------------------
# HTTP METHODS
# -----------------------------------------
class HttpMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"


# -----------------------------------------
# AUTH TYPES (Govt-level required)
# -----------------------------------------
class AuthType(str, Enum):
    NONE = "NONE"
    BASIC = "BASIC"
    BEARER = "BEARER"
    API_KEY = "API_KEY"


class Authorization(BaseModel):
    type: AuthType = AuthType.NONE
    username: Optional[str] = None
    password: Optional[str] = None
    token: Optional[str] = None
    api_key_name: Optional[str] = None
    api_key_value: Optional[str] = None


# -----------------------------------------
# COLLECTION MODEL
# -----------------------------------------
class CreateCollection(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)


# -----------------------------------------
# REQUEST MODEL (Enterprise)
# -----------------------------------------
class CreateRequest(BaseModel):
    name: str = Field(..., max_length=150)
    method: HttpMethod
    url: HttpUrl
    headers: Dict[str, str] = Field(default_factory=dict)
    body: Optional[Any] = None
    authorization: Authorization = Authorization()

    created_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: str = Field(..., description="User ID or Employee ID")

    @validator("headers")
    def validate_header_keys(cls, v):
        for key in v:
            if " " in key:
                raise ValueError("Header keys cannot contain spaces")
        return v
