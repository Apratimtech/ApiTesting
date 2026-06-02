from pydantic import BaseModel
from typing import Dict, Any, List, Optional


# =========================================================
# REQUEST MODEL
# =========================================================

class GraphQLRequest(BaseModel):

    endpoint: str

    query: str

    variables: Optional[Dict[str, Any]] = {}

    headers: Optional[Dict[str, str]] = {}

    auth_type: Optional[str] = "Bearer Token"

    auth_value: Optional[str] = ""


# =========================================================
# SEVERITY ENUM
# =========================================================

class SeverityLevel:

    CRITICAL = "CRITICAL"

    HIGH = "HIGH"

    MEDIUM = "MEDIUM"

    LOW = "LOW"

    INFO = "INFO"


# =========================================================
# SECURITY FINDING MODEL
# =========================================================

class SecurityFinding(BaseModel):

    severity: str

    category: str

    type: str

    title: str

    message: str

    recommendation: str

    impact: str

    owasp: str


# =========================================================
# SECURITY ANALYSIS MODEL
# =========================================================

class SecurityAnalysis(BaseModel):

    risk_score: int

    findings_count: int

    critical_count: int

    high_count: int

    medium_count: int

    low_count: int

    passed_checks: List[str]

    failed_checks: List[str]


# =========================================================
# SECURITY METRICS MODEL
# =========================================================

class SecurityMetrics(BaseModel):

    query_depth: int

    alias_count: int

    query_size: int

    operation_count: int

    introspection_detected: bool

    sensitive_data_detected: bool

    injection_detected: bool


# =========================================================
# REQUEST HEADERS MODEL
# =========================================================

class RequestHeader(BaseModel):

    key: str

    value: str


# =========================================================
# HISTORY ITEM MODEL
# =========================================================

class QueryHistoryItem(BaseModel):

    query_name: str

    endpoint: str

    status_code: int

    response_time: int

    timestamp: str


# =========================================================
# MAIN RESPONSE MODEL
# =========================================================

class GraphQLResponse(BaseModel):

    success: bool

    status_code: int

    response_time: int

    response: Dict[str, Any]

    findings: List[SecurityFinding]

    risk_score: int

    analysis: SecurityAnalysis

    metrics: Optional[SecurityMetrics] = None

    headers: Dict[str, Any]


# =========================================================
# ERROR RESPONSE MODEL
# =========================================================

class ErrorResponse(BaseModel):

    success: bool = False

    error: str

    details: Optional[str] = None
