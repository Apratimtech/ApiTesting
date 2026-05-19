import jwt
import json
import re
import os
import logging
from datetime import datetime, timezone
from typing import Dict, List, Set

from presidio_analyzer import AnalyzerEngine

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
)

logger = logging.getLogger("TrustEdgeAnalyzer")

# ==========================================================
# GROQ AI (Optional)
# ==========================================================
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

groq_client = None

if GROQ_API_KEY:
    try:
        from groq import Groq

        groq_client = Groq(api_key=GROQ_API_KEY)
        logger.info("Groq AI Enabled")

    except Exception as e:
        logger.warning(f"Groq initialization failed: {e}")

# ==========================================================
# PRESIDIO ANALYZER
# ==========================================================
analyzer_engine = AnalyzerEngine()

# ==========================================================
# TRUST EDGE ANALYZER
# ==========================================================
class TrustEdgeAnalyzer:

    # ======================================================
    # MAIN ANALYZE
    # ======================================================
    def analyze(self, payload: Dict) -> Dict:

        logger.info("=" * 80)
        logger.info("NEW ANALYSIS REQUEST")
        logger.info("=" * 80)

        try:
            logger.debug(f"FULL PAYLOAD:\n{json.dumps(payload, indent=2, default=str)}")

            # FIXED PAYLOAD EXTRACTION
            request = payload.get("request", payload)
            response = payload.get("response", {})

            logger.info(f"REQUEST METHOD: {request.get('method')}")
            logger.info(f"REQUEST URL: {request.get('url')}")
            logger.info(f"REQUEST HEADERS: {request.get('headers')}")

            return self.analyze_full_packet(request, response)

        except Exception as e:
            logger.error(f"Analyzer Error: {e}", exc_info=True)

            return {
                "success": False,
                "error": str(e),
                "findings": [],
                "summary": "Analyzer failed",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }

    # ======================================================
    # FULL PACKET ANALYSIS
    # ======================================================
    def analyze_full_packet(self, request: Dict, response: Dict) -> Dict:

        findings: List[Dict] = []

        findings.extend(self._authentication_analysis(request))
        findings.extend(self._jwt_security_analysis(request))
        findings.extend(self._transport_security_analysis(request))
        findings.extend(self._security_headers_analysis(response))
        findings.extend(self._plaintext_analysis(request, response))
        findings.extend(self._sensitive_data_analysis(request, response))
        findings.extend(self._graphql_analysis(request))
        findings.extend(self._rate_limit_analysis(response))
        findings.extend(self._server_leak_analysis(response))
        findings.extend(self._error_analysis(response))
        findings.extend(self._injection_analysis(request))
        findings.extend(self._ai_prompt_injection_analysis(request))
        findings.extend(self._file_upload_analysis(request))
        findings.extend(self._cors_analysis(response))
        findings.extend(self._cookie_analysis(response))
        findings.extend(self._http_method_analysis(request))
        findings.extend(self._content_type_analysis(request))
        findings.extend(self._path_analysis(request))
        findings.extend(self._suspicious_pattern_analysis(request))
        findings.extend(self._token_exposure_analysis(request, response))

        findings = self._deduplicate_findings(findings)

        risk = self._calculate_risk_score(findings)

        return {
            "success": True,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "generated_by": "Trust_Edge Analyzer",
            "method": request.get("method"),
            "analyzed_url": request.get("url"),
            "overall_risk_score": risk["overall_risk_score"],
            "severity": risk["severity"],
            "findings": findings,
            "summary": f"{len(findings)} security findings detected"
        }

    # ======================================================
    # NORMALIZE HEADERS
    # ======================================================
    def _normalize_headers(self, headers: Dict) -> Dict:

        if not isinstance(headers, dict):
            return {}

        return {
            str(k).lower(): str(v)
            for k, v in headers.items()
        }

    # ======================================================
    # DEDUPLICATION
    # ======================================================
    def _deduplicate_findings(self, findings: List[Dict]) -> List[Dict]:

        seen: Set[str] = set()
        unique = []

        for finding in findings:

            key = (
                f"{finding.get('issue')}|"
                f"{finding.get('category')}|"
                f"{finding.get('severity')}"
            )

            if key not in seen:
                seen.add(key)
                unique.append(finding)

        return unique

    # ======================================================
    # RISK SCORE
    # ======================================================
    def _calculate_risk_score(self, findings: List[Dict]) -> Dict:

        severity_weights = {
            "CRITICAL": 10,
            "HIGH": 7,
            "MEDIUM": 5,
            "LOW": 2,
            "INFO": 0
        }

        total_score = 0
        highest = "LOW"

        for finding in findings:

            sev = finding.get("severity", "LOW").upper()

            total_score += severity_weights.get(sev, 0)

            if severity_weights.get(sev, 0) > severity_weights.get(highest, 0):
                highest = sev

        normalized = min(total_score * 4, 100)

        return {
            "overall_risk_score": normalized,
            "severity": highest
        }

    # ======================================================
    # AUTHENTICATION ANALYSIS
    # ======================================================
    def _authentication_analysis(self, request: Dict) -> List[Dict]:

        findings = []

        headers = self._normalize_headers(request.get("headers", {}))

        logger.info(f"NORMALIZED HEADERS: {headers}")

        auth = headers.get("authorization", "").strip()

        logger.info(f"AUTHORIZATION HEADER: {auth}")

        if not auth:

            findings.append({
                "issue": "Missing Authentication",
                "description": "No authentication mechanism detected in request.",
                "severity": "CRITICAL",
                "category": "Authentication",
                "owasp": "API2:2023",
                "cwe": "CWE-306",
                "recommendation": "Implement OAuth2, JWT, API Keys, or session authentication."
            })

            return findings

        # BEARER AUTH
        if auth.lower().startswith("bearer "):

            token = auth[7:].strip()

            if token:

                findings.append({
                    "issue": "Bearer Authentication Detected",
                    "description": "Bearer token authentication detected.",
                    "severity": "INFO",
                    "category": "Authentication"
                })

            else:

                findings.append({
                    "issue": "Empty Bearer Token",
                    "description": "Bearer token is empty.",
                    "severity": "HIGH",
                    "category": "Authentication",
                    "recommendation": "Provide a valid bearer token."
                })

        # BASIC AUTH
        elif auth.lower().startswith("basic "):

            findings.append({
                "issue": "Basic Authentication Detected",
                "description": "Basic authentication detected.",
                "severity": "INFO",
                "category": "Authentication",
                "recommendation": "Prefer OAuth2 or JWT over Basic Auth."
            })

        else:

            findings.append({
                "issue": "Custom Authentication Header",
                "description": "Authentication header detected.",
                "severity": "INFO",
                "category": "Authentication"
            })

        return findings

    # ======================================================
    # JWT ANALYSIS
    # ======================================================
    def _jwt_security_analysis(self, request: Dict) -> List[Dict]:

        findings = []

        headers = self._normalize_headers(request.get("headers", {}))

        auth = headers.get("authorization", "")

        if not auth.lower().startswith("bearer "):
            return findings

        token = auth[7:].strip()

        if not token:
            return findings

        if len(token.split(".")) != 3:

            findings.append({
                "issue": "Invalid JWT Structure",
                "description": "JWT token does not contain 3 sections.",
                "severity": "HIGH",
                "category": "JWT Security"
            })

            return findings

        try:

            header = jwt.get_unverified_header(token)

            jwt.decode(
                token,
                options={
                    "verify_signature": False
                }
            )

            alg = header.get("alg", "unknown")

            if alg.lower() == "none":

                findings.append({
                    "issue": "JWT Uses NONE Algorithm",
                    "description": "JWT token uses insecure NONE algorithm.",
                    "severity": "CRITICAL",
                    "category": "JWT Security",
                    "recommendation": "Use RS256 or ES256."
                })

            elif alg not in ["RS256", "ES256", "HS256"]:

                findings.append({
                    "issue": "Weak JWT Algorithm",
                    "description": f"JWT uses weak algorithm: {alg}",
                    "severity": "HIGH",
                    "category": "JWT Security",
                    "recommendation": "Use RS256 or ES256."
                })

        except Exception as e:

            findings.append({
                "issue": "Invalid JWT Token",
                "description": f"JWT parsing failed: {str(e)}",
                "severity": "HIGH",
                "category": "JWT Security"
            })

        return findings

    # ======================================================
    # TRANSPORT SECURITY
    # ======================================================
    def _transport_security_analysis(self, request: Dict) -> List[Dict]:

        url = str(request.get("url", "")).strip().lower()

        if url.startswith("http://"):

            return [{
                "issue": "Insecure HTTP Transport",
                "description": "Data transmitted over unencrypted HTTP.",
                "severity": "CRITICAL",
                "category": "Transport Security",
                "recommendation": "Use HTTPS with TLS 1.2+."
            }]

        return []

    # ======================================================
    # SECURITY HEADERS
    # ======================================================
    def _security_headers_analysis(self, response: Dict) -> List[Dict]:

        headers = self._normalize_headers(response.get("headers", {}))

        required = [
            "content-security-policy",
            "strict-transport-security",
            "x-content-type-options",
            "x-frame-options",
            "referrer-policy"
        ]

        missing = [h for h in required if h not in headers]

        if missing:

            return [{
                "issue": "Missing Security Headers",
                "description": f"Missing headers: {', '.join(missing)}",
                "severity": "MEDIUM",
                "category": "Security Headers",
                "recommendation": "Add recommended security headers."
            }]

        return []

    # ======================================================
    # PLAINTEXT SENSITIVE DATA
    # ======================================================
    def _plaintext_analysis(self, request: Dict, response: Dict) -> List[Dict]:

        findings = []

        payloads = [
            ("Request", request.get("body")),
            ("Response", response.get("body"))
        ]

        patterns = [
            r'password"\s*:\s*"[^"]+"',
            r'secret"\s*:\s*"[^"]+"',
            r'api[_-]?key"\s*:\s*"[^"]+"'
        ]

        for location, body in payloads:

            if not body:
                continue

            try:

                text = (
                    json.dumps(body)
                    if isinstance(body, (dict, list))
                    else str(body)
                )

                for pattern in patterns:

                    if re.search(pattern, text, re.IGNORECASE):

                        findings.append({
                            "issue": "Sensitive Data Sent in Plaintext",
                            "description": f"{location} contains sensitive plaintext secrets.",
                            "severity": "CRITICAL",
                            "category": "Data Protection",
                            "recommendation": "Encrypt or mask sensitive data."
                        })

                        break

            except Exception:
                pass

        return findings

    # ======================================================
    # PII ANALYSIS
    # ======================================================
    def _sensitive_data_analysis(self, request: Dict, response: Dict) -> List[Dict]:

        findings = []

        for location, body in [
            ("Request", request.get("body")),
            ("Response", response.get("body"))
        ]:

            if not body:
                continue

            try:

                text = (
                    json.dumps(body)
                    if isinstance(body, (dict, list))
                    else str(body)
                )

                results = analyzer_engine.analyze(
                    text=text,
                    language="en"
                )

                for result in results:

                    if result.score > 0.65:

                        findings.append({
                            "issue": f"Sensitive Data Exposure ({result.entity_type})",
                            "description": f"Detected {result.entity_type} in {location}.",
                            "severity": "HIGH",
                            "category": "PII Exposure",
                            "recommendation": "Mask or encrypt sensitive information."
                        })

                        break

            except Exception:
                pass

        return findings

    # ======================================================
    # GRAPHQL
    # ======================================================
    def _graphql_analysis(self, request: Dict) -> List[Dict]:

        body_type = str(request.get("bodyType", "")).lower()

        headers = self._normalize_headers(request.get("headers", {}))

        content_type = headers.get("content-type", "").lower()

        if (
            body_type == "graphql"
            or "graphql" in content_type
        ):

            return [{
                "issue": "GraphQL Endpoint Detected",
                "description": "GraphQL endpoints may expose introspection risks.",
                "severity": "MEDIUM",
                "category": "GraphQL Security",
                "recommendation": "Disable GraphQL introspection in production."
            }]

        return []

    # ======================================================
    # RATE LIMIT
    # ======================================================
    def _rate_limit_analysis(self, response: Dict) -> List[Dict]:

        headers = self._normalize_headers(response.get("headers", {}))

        if not any(
            h in headers
            for h in [
                "x-ratelimit-limit",
                "ratelimit-limit"
            ]
        ):

            return [{
                "issue": "Missing Rate Limiting",
                "description": "No rate limiting headers detected.",
                "severity": "HIGH",
                "category": "Availability",
                "recommendation": "Implement API rate limiting."
            }]

        return []

    # ======================================================
    # SERVER LEAK
    # ======================================================
    def _server_leak_analysis(self, response: Dict) -> List[Dict]:

        headers = self._normalize_headers(response.get("headers", {}))

        if "server" in headers:

            return [{
                "issue": "Server Information Disclosure",
                "description": f"Server header exposed: {headers['server']}",
                "severity": "MEDIUM",
                "category": "Information Disclosure",
                "recommendation": "Hide or minimize server banners."
            }]

        return []

    # ======================================================
    # ERROR ANALYSIS
    # ======================================================
    def _error_analysis(self, response: Dict) -> List[Dict]:

        status = response.get("status")

        if status in [500, 502, 503]:

            return [{
                "issue": "Server Error Response",
                "description": "Server returned internal error.",
                "severity": "HIGH",
                "category": "Error Handling",
                "recommendation": "Avoid exposing internal server errors."
            }]

        return []

    # ======================================================
    # INJECTION ANALYSIS
    # ======================================================
    def _injection_analysis(self, request: Dict) -> List[Dict]:

        body = str(request.get("body", "")).lower()

        patterns = [
            "union select",
            "' or 1=1",
            "<script>",
            "javascript:",
            "drop table",
            "../../",
            "xp_cmdshell"
        ]

        if any(x in body for x in patterns):

            return [{
                "issue": "Potential Injection Attempt",
                "description": "Suspicious injection payload detected.",
                "severity": "CRITICAL",
                "category": "Injection Attack",
                "recommendation": "Sanitize and validate all user inputs."
            }]

        return []

    # ======================================================
    # AI PROMPT INJECTION
    # ======================================================
    def _ai_prompt_injection_analysis(self, request: Dict) -> List[Dict]:

        body = str(request.get("body", "")).lower()

        prompts = [
            "ignore previous instructions",
            "bypass safety",
            "reveal system prompt"
        ]

        if any(p in body for p in prompts):

            return [{
                "issue": "AI Prompt Injection Attempt",
                "description": "Potential AI prompt injection detected.",
                "severity": "HIGH",
                "category": "AI Security",
                "recommendation": "Sanitize prompts and isolate model instructions."
            }]

        return []

    # ======================================================
    # FILE UPLOAD
    # ======================================================
    def _file_upload_analysis(self, request: Dict) -> List[Dict]:

        headers = self._normalize_headers(request.get("headers", {}))

        content_type = headers.get("content-type", "").lower()

        if "multipart/form-data" in content_type:

            return [{
                "issue": "File Upload Endpoint Detected",
                "description": "File upload detected. Ensure strict validation.",
                "severity": "HIGH",
                "category": "File Upload Security",
                "recommendation": "Validate file types, size, and scan uploads."
            }]

        return []

    # ======================================================
    # CORS
    # ======================================================
    def _cors_analysis(self, response: Dict) -> List[Dict]:

        headers = self._normalize_headers(response.get("headers", {}))

        origin = headers.get("access-control-allow-origin")

        if origin == "*":

            return [{
                "issue": "Permissive CORS Policy",
                "description": "Wildcard CORS policy detected.",
                "severity": "HIGH",
                "category": "CORS Security",
                "recommendation": "Restrict CORS to trusted domains."
            }]

        return []

    # ======================================================
    # COOKIE ANALYSIS
    # ======================================================
    def _cookie_analysis(self, response: Dict) -> List[Dict]:

        findings = []

        headers = self._normalize_headers(response.get("headers", {}))

        cookie = headers.get("set-cookie", "").lower()

        if not cookie:
            return findings

        if "httponly" not in cookie:

            findings.append({
                "issue": "Cookie Missing HttpOnly",
                "description": "Cookie accessible via JavaScript.",
                "severity": "HIGH",
                "category": "Cookie Security",
                "recommendation": "Add HttpOnly flag."
            })

        if "secure" not in cookie:

            findings.append({
                "issue": "Cookie Missing Secure Flag",
                "description": "Cookie may be transmitted over HTTP.",
                "severity": "HIGH",
                "category": "Cookie Security",
                "recommendation": "Add Secure flag."
            })

        return findings

    # ======================================================
    # HTTP METHODS
    # ======================================================
    def _http_method_analysis(self, request: Dict) -> List[Dict]:

        method = str(request.get("method", "")).upper()

        if method in ["TRACE", "CONNECT"]:

            return [{
                "issue": f"Dangerous HTTP Method ({method})",
                "description": f"Use of dangerous HTTP method: {method}",
                "severity": "HIGH",
                "category": "HTTP Security",
                "recommendation": "Disable dangerous HTTP methods."
            }]

        return []

    # ======================================================
    # CONTENT TYPE
    # ======================================================
    def _content_type_analysis(self, request: Dict) -> List[Dict]:

        headers = self._normalize_headers(request.get("headers", {}))

        content_type = headers.get("content-type", "").lower()

        if "text/plain" in content_type:

            return [{
                "issue": "Plaintext Content-Type",
                "description": "Using plaintext content-type.",
                "severity": "MEDIUM",
                "category": "Transport Security",
                "recommendation": "Use secure structured content-types."
            }]

        return []

    # ======================================================
    # PATH ANALYSIS
    # ======================================================
    def _path_analysis(self, request: Dict) -> List[Dict]:

        url = str(request.get("url", "")).lower()

        sensitive_paths = [
            "/admin",
            "/debug",
            "/config",
            "/actuator",
            "/swagger",
            "/internal"
        ]

        for path in sensitive_paths:

            if path in url:

                return [{
                    "issue": "Sensitive Endpoint Detected",
                    "description": f"Sensitive path detected: {path}",
                    "severity": "HIGH",
                    "category": "Endpoint Exposure",
                    "recommendation": "Protect sensitive endpoints with authentication."
                }]

        return []

    # ======================================================
    # SUSPICIOUS PAYLOADS
    # ======================================================
    def _suspicious_pattern_analysis(self, request: Dict) -> List[Dict]:

        body = str(request.get("body", "")).lower()

        patterns = [
            "nc -e",
            "/etc/passwd",
            "powershell",
            "cmd.exe",
            "bash -i",
            "whoami"
        ]

        if any(p in body for p in patterns):

            return [{
                "issue": "Suspicious Payload Detected",
                "description": "Potential malicious payload detected.",
                "severity": "CRITICAL",
                "category": "Malicious Payload",
                "recommendation": "Block malicious command patterns."
            }]

        return []

    # ======================================================
    # TOKEN EXPOSURE
    # ======================================================
    def _token_exposure_analysis(
        self,
        request: Dict,
        response: Dict
    ) -> List[Dict]:

        text = (
            str(request.get("body", ""))
            + str(response.get("body", ""))
        )

        patterns = [
            r"sk_live_[A-Za-z0-9]+",
            r"ghp_[A-Za-z0-9]+",
            r"AIza[0-9A-Za-z-_]+"
        ]

        for pattern in patterns:

            if re.search(pattern, text):

                return [{
                    "issue": "Exposed API Secret",
                    "description": "Potential secret key exposure detected.",
                    "severity": "CRITICAL",
                    "category": "Secret Exposure",
                    "recommendation": "Remove exposed secrets immediately."
                }]

        return []


# ==========================================================
# INSTANCE
# ==========================================================
analyzer = TrustEdgeAnalyzer()
