# 📁 schemas/analyzer.py

from pydantic import BaseModel, Field, HttpUrl, validator
from typing import Dict, Any, Optional
from datetime import datetime

from .collection import HttpMethod


class AnalyzeRequest(BaseModel):
    # Which request is being analyzed
    id: str = Field(..., description="Request ID")

    # HTTP method and URL
    method: HttpMethod
    url: HttpUrl

    # Request data
    headers: Dict[str, str] = Field(default_factory=dict)
    body: Optional[Any] = None

    # Audit metadata (important for govt-level systems)
    analyzed_at: datetime = Field(default_factory=datetime.utcnow)
    analyzed_by: Optional[str] = Field(
        None, description="User ID or Employee ID performing the analysis"
    )

    # Optional system fields for deep analysis
    source_system: Optional[str] = Field(
        None, description="Name of system sending the request"
    )
    environment: Optional[str] = Field(
        None, description="prod / uat / dev"
    )

    # -----------------------------
    # VALIDATORS (Security layer)
    # -----------------------------

    @validator("headers")
    def validate_headers(cls, v):
        if not isinstance(v, dict):
            raise ValueError("Headers must be a dictionary")

        for key, value in v.items():
            # No spaces in header keys (industry rule)
            if " " in key:
                raise ValueError(f"Header name '{key}' contains spaces")

            # Header keys must be strings
            if not isinstance(key, str):
                raise ValueError("Header keys must be strings")

            # Header values must be str or convertible to str
            if not isinstance(value, (str, int, float)):
                raise ValueError("Header values must be string or number")

        return v

    @validator("id")
    def validate_id(cls, v):
        if len(v.strip()) == 0:
            raise ValueError("ID cannot be empty")
        return v
