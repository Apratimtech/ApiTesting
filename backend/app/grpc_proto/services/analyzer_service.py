import json
import logging
import re
import time
import traceback
import uuid
from datetime import datetime
from typing import Dict, List, Set

import grpc

from app.grpc_proto.generated import (
    analyzer_pb2,
    analyzer_pb2_grpc,
)

# =========================================================
# LOGGER
# =========================================================

logger = logging.getLogger(
    "trustedge.grpc.security"
)

logging.basicConfig(
    level=logging.INFO,
    format=(
        "[%(asctime)s] "
        "[%(levelname)s] "
        "[%(name)s] "
        "%(message)s"
    ),
)

# =========================================================
# SECURITY CONSTANTS
# =========================================================

MAX_PAYLOAD_SIZE = 1024 * 1024

# =========================================================
# SQL INJECTION
# =========================================================

SQLI_PATTERNS = [
    r"(\bor\b\s+\d+\=\d+)",
    r"(union\s+select)",
    r"(drop\s+table)",
    r"(insert\s+into)",
    r"(delete\s+from)",
    r"(--)",
    r"(\bshutdown\b)",
]

# =========================================================
# XSS
# =========================================================

XSS_PATTERNS = [
    r"<script.*?>",
    r"javascript:",
    r"onerror\s*=",
    r"onload\s*=",
    r"<iframe",
]

# =========================================================
# PATH TRAVERSAL
# =========================================================

PATH_TRAVERSAL = [
    "../",
    "..\\",
    "%2e%2e%2f",
]

# =========================================================
# COMMAND INJECTION
# =========================================================

COMMAND_INJECTION = [
    r";\s*cat\s+",
    r";\s*ls\s+",
    r";\s*rm\s+",
    r"\|\s*bash",
    r"&&",
]

# =========================================================
# SSRF
# =========================================================

SSRF_PATTERNS = [
    "127.0.0.1",
    "localhost",
    "169.254.169.254",
    "::1",
]

# =========================================================
# PROMPT INJECTION
# =========================================================

PROMPT_INJECTION = [
    "ignore previous instructions",
    "system prompt",
    "bypass safety",
]

# =========================================================
# GRAPHQL ATTACKS
# =========================================================

GRAPHQL_ATTACKS = [
    "__schema",
    "__type",
    "mutation",
]

# =========================================================
# XML ATTACKS
# =========================================================

XML_ATTACKS = [
    "<!ENTITY",
    "<!DOCTYPE",
]

# =========================================================
# NOSQL INJECTION
# =========================================================

NOSQL_ATTACKS = [
    "$ne",
    "$gt",
    "$regex",
]

# =========================================================
# LDAP INJECTION
# =========================================================

LDAP_ATTACKS = [
    "*)(",
    "admin*)",
]

# =========================================================
# CRLF INJECTION
# =========================================================

CRLF_ATTACKS = [
    "%0d%0a",
    "\r\n",
]

# =========================================================
# RCE PATTERNS
# =========================================================

RCE_PATTERNS = [
    "powershell",
    "/bin/bash",
    "cmd.exe",
]

# =========================================================
# SECRET LEAKS
# =========================================================

SECRET_PATTERNS = [
    "aws_secret_access_key",
    "private_key",
    "begin rsa private key",
]

# =========================================================
# API KEY LEAKS
# =========================================================

API_KEY_PATTERNS = [
    "apikey",
    "x-api-key",
    "bearer ",
]

# =========================================================
# JWT WEAKNESS
# =========================================================

WEAK_JWT = [
    "alg:none",
    "\"alg\":\"none\"",
]

# =========================================================
# PII DETECTION
# =========================================================

PII_PATTERNS = [
    r"\b\d{16}\b",
    r"\b\d{3}-\d{2}-\d{4}\b",
]

# =========================================================
# SENSITIVE HEADERS
# =========================================================

SENSITIVE_HEADERS = {
    "server",
    "x-powered-by",
    "grpc-status-details-bin",
}

# =========================================================
# ANALYZER SERVICE
# =========================================================


class AnalyzerService(
    analyzer_pb2_grpc.AnalyzerServiceServicer
):

    async def Analyze(
        self,
        request,
        context,
    ):

        start = time.perf_counter()

        correlation_id = str(
            uuid.uuid4()
        )

        findings: List[Dict] = []

        detected: Set[str] = set()

        risk_score = 0

        try:

            # =================================================
            # REQUEST EXTRACTION
            # =================================================

            target = str(
                getattr(request, "target", "")
            )

            method = str(
                getattr(request, "method", "")
            )

            payload = str(
                getattr(request, "payload", "")
            )

            metadata = getattr(
                request,
                "metadata",
                []
            )

            metadata_dict = self._metadata_to_dict(
                metadata
            )

            normalized_payload = (
                payload.lower().strip()
            )

            logger.info(
                f"[{correlation_id}] "
                f"Analyzing method={method}"
            )

            # =================================================
            # PAYLOAD SIZE VALIDATION
            # =================================================

            if len(payload) > MAX_PAYLOAD_SIZE:

                await context.abort(
                    grpc.StatusCode.INVALID_ARGUMENT,
                    "Payload too large"
                )

            # =================================================
            # BROKEN AUTHENTICATION
            # =================================================

            if (
                "authorization"
                not in metadata_dict
            ):

                self.add_finding(
                    findings,
                    detected,
                    "broken_auth",
                    {
                        "severity": "CRITICAL",
                        "owasp": "API2:2023",
                        "title": "Broken Authentication",
                        "description": (
                            "Authorization token missing"
                        ),
                    },
                )

                risk_score += 30

            # =================================================
            # TLS VALIDATION
            # =================================================

            if target.startswith("http://"):

                self.add_finding(
                    findings,
                    detected,
                    "insecure_transport",
                    {
                        "severity": "HIGH",
                        "owasp": "API8:2023",
                        "title": "Insecure Transport",
                        "description": (
                            "TLS not enabled"
                        ),
                    },
                )

                risk_score += 20

            # =================================================
            # SQLi
            # =================================================

            for pattern in SQLI_PATTERNS:

                if re.search(
                    pattern,
                    normalized_payload,
                    re.IGNORECASE,
                ):

                    self.add_finding(
                        findings,
                        detected,
                        pattern,
                        {
                            "severity": "CRITICAL",
                            "owasp": "API8:2023",
                            "title": "SQL Injection",
                            "description": (
                                f"Detected pattern: "
                                f"{pattern}"
                            ),
                        },
                    )

                    risk_score += 25

            # =================================================
            # XSS
            # =================================================

            for pattern in XSS_PATTERNS:

                if re.search(
                    pattern,
                    normalized_payload,
                    re.IGNORECASE,
                ):

                    self.add_finding(
                        findings,
                        detected,
                        pattern,
                        {
                            "severity": "HIGH",
                            "owasp": "API8:2023",
                            "title": "XSS Attack",
                            "description": (
                                f"Detected pattern: "
                                f"{pattern}"
                            ),
                        },
                    )

                    risk_score += 20

            # =================================================
            # PATH TRAVERSAL
            # =================================================

            for pattern in PATH_TRAVERSAL:

                if pattern in normalized_payload:

                    self.add_finding(
                        findings,
                        detected,
                        pattern,
                        {
                            "severity": "HIGH",
                            "owasp": "API1:2023",
                            "title": "Path Traversal",
                            "description": (
                                "Traversal payload detected"
                            ),
                        },
                    )

                    risk_score += 15

            # =================================================
            # COMMAND INJECTION
            # =================================================

            for pattern in COMMAND_INJECTION:

                if re.search(
                    pattern,
                    normalized_payload,
                    re.IGNORECASE,
                ):

                    self.add_finding(
                        findings,
                        detected,
                        pattern,
                        {
                            "severity": "CRITICAL",
                            "owasp": "API8:2023",
                            "title": "Command Injection",
                            "description": (
                                f"Detected pattern: "
                                f"{pattern}"
                            ),
                        },
                    )

                    risk_score += 30

            # =================================================
            # SSRF
            # =================================================

            for item in SSRF_PATTERNS:

                if item in normalized_payload:

                    self.add_finding(
                        findings,
                        detected,
                        item,
                        {
                            "severity": "HIGH",
                            "owasp": "API7:2023",
                            "title": "SSRF Attempt",
                            "description": (
                                f"Internal target detected: "
                                f"{item}"
                            ),
                        },
                    )

                    risk_score += 20

            # =================================================
            # GRAPHQL ATTACKS
            # =================================================

            for item in GRAPHQL_ATTACKS:

                if item.lower() in normalized_payload:

                    self.add_finding(
                        findings,
                        detected,
                        item,
                        {
                            "severity": "MEDIUM",
                            "owasp": "API8:2023",
                            "title": "GraphQL Enumeration",
                            "description": (
                                f"Detected GraphQL attack: {item}"
                            ),
                        },
                    )

                    risk_score += 10

            # =================================================
            # XML ATTACKS
            # =================================================

            for item in XML_ATTACKS:

                if item.lower() in normalized_payload:

                    self.add_finding(
                        findings,
                        detected,
                        item,
                        {
                            "severity": "HIGH",
                            "owasp": "API8:2023",
                            "title": "XML Injection",
                            "description": (
                                f"Detected XML payload: {item}"
                            ),
                        },
                    )

                    risk_score += 20

            # =================================================
            # NOSQL INJECTION
            # =================================================

            for item in NOSQL_ATTACKS:

                if item.lower() in normalized_payload:

                    self.add_finding(
                        findings,
                        detected,
                        item,
                        {
                            "severity": "CRITICAL",
                            "owasp": "API8:2023",
                            "title": "NoSQL Injection",
                            "description": (
                                f"Detected operator: {item}"
                            ),
                        },
                    )

                    risk_score += 25

            # =================================================
            # LDAP INJECTION
            # =================================================

            for item in LDAP_ATTACKS:

                if item.lower() in normalized_payload:

                    self.add_finding(
                        findings,
                        detected,
                        item,
                        {
                            "severity": "HIGH",
                            "owasp": "API8:2023",
                            "title": "LDAP Injection",
                            "description": (
                                f"Detected LDAP payload: {item}"
                            ),
                        },
                    )

                    risk_score += 20

            # =================================================
            # CRLF INJECTION
            # =================================================

            for item in CRLF_ATTACKS:

                if item.lower() in normalized_payload:

                    self.add_finding(
                        findings,
                        detected,
                        item,
                        {
                            "severity": "MEDIUM",
                            "owasp": "API8:2023",
                            "title": "CRLF Injection",
                            "description": (
                                "Detected CRLF payload"
                            ),
                        },
                    )

                    risk_score += 10

            # =================================================
            # RCE DETECTION
            # =================================================

            for item in RCE_PATTERNS:

                if item.lower() in normalized_payload:

                    self.add_finding(
                        findings,
                        detected,
                        item,
                        {
                            "severity": "CRITICAL",
                            "owasp": "API8:2023",
                            "title": "Remote Code Execution",
                            "description": (
                                f"RCE payload detected: {item}"
                            ),
                        },
                    )

                    risk_score += 35

            # =================================================
            # SECRET LEAK DETECTION
            # =================================================

            for item in SECRET_PATTERNS:

                if item.lower() in normalized_payload:

                    self.add_finding(
                        findings,
                        detected,
                        item,
                        {
                            "severity": "CRITICAL",
                            "owasp": "API3:2023",
                            "title": "Secret Leakage",
                            "description": (
                                "Sensitive secret exposed"
                            ),
                        },
                    )

                    risk_score += 40

            # =================================================
            # API KEY LEAK DETECTION
            # =================================================

            for item in API_KEY_PATTERNS:

                if item.lower() in normalized_payload:

                    self.add_finding(
                        findings,
                        detected,
                        item,
                        {
                            "severity": "HIGH",
                            "owasp": "API2:2023",
                            "title": "API Key Exposure",
                            "description": (
                                "Credential exposure detected"
                            ),
                        },
                    )

                    risk_score += 15

            # =================================================
            # PII DETECTION
            # =================================================

            for pattern in PII_PATTERNS:

                if re.search(
                    pattern,
                    normalized_payload,
                    re.IGNORECASE,
                ):

                    self.add_finding(
                        findings,
                        detected,
                        pattern,
                        {
                            "severity": "HIGH",
                            "owasp": "API3:2023",
                            "title": "PII Exposure",
                            "description": (
                                "Sensitive personal data detected"
                            ),
                        },
                    )

                    risk_score += 20

            # =================================================
            # PROMPT INJECTION
            # =================================================

            for item in PROMPT_INJECTION:

                if item in normalized_payload:

                    self.add_finding(
                        findings,
                        detected,
                        item,
                        {
                            "severity": "MEDIUM",
                            "owasp": "LLM01",
                            "title": "Prompt Injection",
                            "description": (
                                f"Detected phrase: {item}"
                            ),
                        },
                    )

                    risk_score += 10

            # =================================================
            # JWT VALIDATION
            # =================================================

            auth = metadata_dict.get(
                "authorization",
                ""
            )

            auth_lower = auth.lower()

            for weak in WEAK_JWT:

                if weak in auth_lower:

                    self.add_finding(
                        findings,
                        detected,
                        weak,
                        {
                            "severity": "HIGH",
                            "owasp": "API2:2023",
                            "title": "Weak JWT",
                            "description": (
                                f"Weak JWT algorithm: "
                                f"{weak}"
                            ),
                        },
                    )

                    risk_score += 15

            # =================================================
            # SENSITIVE HEADERS
            # =================================================

            for header in metadata_dict.keys():

                if (
                    header.lower()
                    in SENSITIVE_HEADERS
                ):

                    self.add_finding(
                        findings,
                        detected,
                        header,
                        {
                            "severity": "LOW",
                            "owasp": "API8:2023",
                            "title": "Sensitive Header Leak",
                            "description": (
                                f"Header exposed: {header}"
                            ),
                        },
                    )

                    risk_score += 5

            # =================================================
            # ADMIN EXPOSURE
            # =================================================

            if "admin" in method.lower():

                self.add_finding(
                    findings,
                    detected,
                    "admin_method",
                    {
                        "severity": "HIGH",
                        "owasp": "API5:2023",
                        "title": (
                            "Broken Function Level Auth"
                        ),
                        "description": (
                            "Admin endpoint exposed"
                        ),
                    },
                )

                risk_score += 20

            # =================================================
            # AI THREAT CLASSIFIER
            # =================================================

            attack_types = [
                finding["title"]
                for finding in findings
            ]

            threat_category = "NORMAL"

            if any(
                "Injection" in x
                for x in attack_types
            ):
                threat_category = "INJECTION_ATTACK"

            elif any(
                "Execution" in x
                for x in attack_types
            ):
                threat_category = "RCE_ATTACK"

            elif any(
                "Authentication" in x
                for x in attack_types
            ):
                threat_category = "AUTH_ATTACK"

            confidence_score = min(
                100,
                50 + len(findings) * 5
            )

            # =================================================
            # RISK LEVEL
            # =================================================

            risk_score = min(
                risk_score,
                100
            )

            if risk_score >= 80:
                risk_level = "CRITICAL"

            elif risk_score >= 60:
                risk_level = "HIGH"

            elif risk_score >= 30:
                risk_level = "MEDIUM"

            else:
                risk_level = "LOW"

            # =================================================
            # EXECUTION TIME
            # =================================================

            elapsed = round(
                (
                    time.perf_counter() - start
                ) * 1000,
                2,
            )

            logger.info(
                f"[{correlation_id}] "
                f"Risk={risk_score} "
                f"Level={risk_level} "
                f"Time={elapsed}ms"
            )

            # =================================================
            # RESPONSE
            # =================================================

            return analyzer_pb2.AnalyzeResponse(
                success=True,
                message=(
                    "Enterprise OWASP "
                    "security analysis completed"
                ),
                riskScore=risk_score,
                riskLevel=risk_level,
                executionTime=f"{elapsed}ms",
                timestamp=datetime.utcnow().isoformat(),
                findings=json.dumps(
                    findings,
                    indent=2
                ),
                threatCategory=threat_category,
                confidenceScore=confidence_score,
                correlationId=correlation_id,
            )

        except Exception as exc:

            logger.error(
                f"[{correlation_id}] "
                f"{str(exc)}"
            )

            traceback.print_exc()

            await context.abort(
                grpc.StatusCode.INTERNAL,
                "Analyzer execution failed"
            )

    # =====================================================
    # ADD FINDING
    # =====================================================

    def add_finding(
        self,
        findings,
        detected,
        key,
        finding,
    ):

        if key not in detected:

            findings.append(finding)

            detected.add(key)

    # =====================================================
    # METADATA PARSER
    # =====================================================

    def _metadata_to_dict(
        self,
        metadata,
    ) -> Dict:

        result = {}

        try:

            for item in metadata:

                key = str(
                    getattr(item, "key", "")
                ).lower()

                value = str(
                    getattr(item, "value", "")
                )

                result[key] = value

        except Exception as exc:

            logger.warning(
                f"Metadata parse failed: "
                f"{str(exc)}"
            )

        return result
