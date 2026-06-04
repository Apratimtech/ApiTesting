import jwt
import json
import re
import os
import math
import logging
import traceback
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s")
logger = logging.getLogger("TrustEdgeAnalyzer")

# Optional Dependencies
try:
    from presidio_analyzer import AnalyzerEngine
    _presidio = AnalyzerEngine()
except Exception:
    _presidio = None

_groq_client = None
if os.getenv("GROQ_API_KEY"):
    try:
        from groq import Groq
        _groq_client = Groq(api_key=os.getenv("GROQ_API_KEY"))
    except Exception:
        pass

_PUBLIC_TEST_HOSTS = re.compile(r"(httpbin|jsonplaceholder|reqres|postman-echo|mockapi|beeceptor|webhook)", re.I)

# ==================== CONFIG ====================
_SEVERITY_WEIGHT = {"CRITICAL": 15, "HIGH": 8, "MEDIUM": 4, "LOW": 1, "INFO": 0}

_STRONG_ALGS = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256"}
_ACCEPTABLE_ALGS = _STRONG_ALGS | {"HS256"}

_MAX_BODY_LEN = 80000

# Public paths that should not trigger "No Authentication"
_PUBLIC_PATHS = re.compile(
    r"/(login|register|signup|forgot-password|reset-password|health|ping|status|docs|swagger|openapi|public|static|favicon|robots\.txt)",
    re.I
)

def _finding(issue: str, description: str, severity: str, category: str, recommendation: str = "", owasp: str = "", cwe: str = ""):
    return {
        "issue": issue,
        "description": description,
        "severity": severity.upper(),
        "category": category,
        "recommendation": recommendation,
        "owasp": owasp,
        "cwe": cwe
    }


class TrustEdgeAnalyzer:

    def analyze(self, payload: Dict) -> Dict:
        try:
            request = payload.get("request", {}) if isinstance(payload.get("request"), dict) else payload
            response = payload.get("response", {}) if isinstance(payload.get("response"), dict) else {}

            url = str(request.get("url", "")).strip()
            method = str(request.get("method", "GET")).upper()
            is_test_host = bool(_PUBLIC_TEST_HOSTS.search(url))

            findings = self._analyze_packet(request, response, is_test_host, url, method)

            if _groq_client and self._should_call_ai(findings):
                ai = self._groq_enhance(request, findings)
                if ai:
                    findings.append(ai)

            findings = self._deduplicate(findings)
            risk = self._risk_score(findings)

            return {
                "success": True,
                "generated_by": "Trust_Edge Analyzer v2.5",
                "method": method,
                "analyzed_url": url,
                "overall_risk_score": risk["score"],
                "severity": risk["highest"],
                "findings": sorted(findings, key=lambda f: _SEVERITY_WEIGHT.get(f["severity"], 0), reverse=True),
                "summary": f"{len(findings)} security finding(s)",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        except Exception as e:
            logger.error(traceback.format_exc())
            return {
                "success": False,
                "error": str(e),
                "severity": "LOW",
                "findings": []
            }

    def _should_call_ai(self, findings):
        critical = sum(1 for f in findings if f["severity"] == "CRITICAL")
        score = self._risk_score(findings)["score"]
        return critical > 0 or score > 65

    def _analyze_packet(self, request: Dict, response: Dict, is_test_host: bool, url: str, method: str) -> List[Dict]:
        findings = []

        checks = [
            self._check_transport_security,
            self._check_authentication,
            self._check_bearer_token,
            self._check_jwt_detailed,
            self._check_security_headers,
            self._check_plaintext_credentials,
            self._check_pii,
            self._check_rate_limiting,
            self._check_injection,
            self._check_token_exposure,
            self._check_sensitive_paths,
            self._check_suspicious_payloads,
            self._check_response_leaks,
            self._check_idor_bola_indicators,
            self._check_excessive_data_exposure,
            self._check_mass_assignment,
            self._check_ssrf_indicators,
            self._check_xxe_indicators,
        ]

        for check in checks:
            try:
                findings.extend(check(request, response, is_test_host, url, method))
            except Exception as e:
                logger.warning(f"Check {check.__name__} failed: {e}")

        return findings

    def _groq_enhance(self, request, findings):
        try:
            prompt = f"Analyze API security risks for URL: {request.get('url')}\nFindings: {[f['issue'] for f in findings]}\nProvide concise, actionable insight (max 180 chars):"
            resp = _groq_client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=120,
                temperature=0.3
            )
            content = resp.choices[0].message.content.strip()
            return _finding("AI Security Insight", content[:200], "MEDIUM", "AI Analysis")
        except:
            return None

    # ==================== HELPERS ====================
    def _headers(self, obj):
        h = obj.get("headers", {}) or {}
        return {str(k).lower().strip(): str(v).strip() for k, v in h.items() if v is not None}

    def _body_text(self, obj):
        if not obj: return ""
        b = obj.get("body") or obj.get("rawText", "")
        if isinstance(b, (dict, list)):
            try: return json.dumps(b)[:_MAX_BODY_LEN]
            except: pass
        return str(b)[:_MAX_BODY_LEN]

    def _deduplicate(self, findings):
        seen = set()
        return [f for f in findings if (k := f"{f['issue']}|{f.get('category')}") not in seen and not seen.add(k)]

    def _risk_score(self, findings):
        raw = sum(_SEVERITY_WEIGHT.get(f.get("severity"), 0) for f in findings)
        score = round(100 * (1 - math.exp(-0.055 * raw)))
        highest = max(findings, key=lambda f: _SEVERITY_WEIGHT.get(f.get("severity"), 0), default={"severity": "LOW"})
        return {"score": score, "highest": highest["severity"]}

    # ==================== SECURITY CHECKS ====================

    def _check_transport_security(self, request, *args):
        if str(request.get("url", "")).lower().startswith("http://"):
            return [_finding("Insecure HTTP", "Data transmitted over unencrypted channel", "CRITICAL", "Transport Security", owasp="API8:2023", cwe="CWE-319")]
        return []

    def _check_authentication(self, request, response, is_test_host, url, method):
        if _PUBLIC_PATHS.search(url):
            return []
        headers = self._headers(request)
        if not any(headers.get(x) for x in ["authorization", "x-api-key", "x-auth-token", "cookie"]):
            return [_finding("No Authentication", "No authentication mechanism detected on protected endpoint", "CRITICAL", "Authentication", owasp="API2:2023", cwe="CWE-306")]
        return []

    def _check_bearer_token(self, request, *args):
        auth = self._headers(request).get("authorization", "")
        if not auth.lower().startswith("bearer "):
            return []
        token = auth[7:].strip()
        findings = [_finding("Bearer Token Used", "Bearer authentication scheme detected", "LOW", "Authentication")]
        if len(token) < 20:
            findings.append(_finding("Weak Bearer Token", "Token appears too short", "HIGH", "Authentication"))
        return findings

    def _check_jwt_detailed(self, request, *args):
        auth = self._headers(request).get("authorization", "")
        if not auth.lower().startswith("bearer "):
            return []
        token = auth[7:].strip()
        if len(token.split(".")) != 3:
            return [_finding("Malformed JWT", "Invalid JWT format", "HIGH", "JWT Security")]

        findings = []
        try:
            header = jwt.get_unverified_header(token)
            payload = jwt.decode(token, options={"verify_signature": False})

            alg = str(header.get("alg", "")).upper()
            if alg == "NONE":
                findings.append(_finding("JWT alg=none", "Unsigned JWT - Critical vulnerability", "CRITICAL", "JWT Security", owasp="API2:2023", cwe="CWE-347"))
            elif alg not in _ACCEPTABLE_ALGS:
                findings.append(_finding(f"Weak JWT Algorithm: {alg}", "Weak signing algorithm used", "HIGH", "JWT Security"))

            now = datetime.now(timezone.utc).timestamp()

            if not payload.get("iss"):
                findings.append(_finding("JWT Missing iss claim", "Missing issuer validation", "MEDIUM", "JWT Security"))
            if not payload.get("sub"):
                findings.append(_finding("JWT Missing sub claim", "Missing subject", "MEDIUM", "JWT Security"))
            if not payload.get("aud"):
                findings.append(_finding("JWT Missing aud claim", "Missing audience validation", "LOW", "JWT Security"))

            exp = payload.get("exp")
            if exp:
                if exp < now - 300:
                    findings.append(_finding("JWT Expired", "Token has expired", "HIGH", "JWT Security", cwe="CWE-613"))
                elif exp > now + 86400 * 30:
                    findings.append(_finding("JWT Extremely Long Expiry", "Token valid for unusually long period", "MEDIUM", "JWT Security"))
            else:
                findings.append(_finding("JWT Missing exp claim", "Token never expires", "MEDIUM", "JWT Security", cwe="CWE-613"))

            if payload.get("iat") and payload["iat"] > now + 300:
                findings.append(_finding("JWT Future iat", "Issued in the future", "MEDIUM", "JWT Security"))
            if payload.get("nbf") and payload["nbf"] > now + 300:
                findings.append(_finding("JWT Future nbf", "Not yet valid (nbf in future)", "MEDIUM", "JWT Security"))
            if not payload.get("jti"):
                findings.append(_finding("JWT Missing jti", "No JWT ID - higher replay risk", "LOW", "JWT Security"))

        except Exception as e:
            findings.append(_finding("JWT Parse Error", str(e)[:120], "MEDIUM", "JWT Security"))
        return findings

    # ==================== REDESIGNED PLAINTEXT CHECK ====================
    def _check_plaintext_credentials(self, request, response, *args):
        """High-standard detection of sensitive data sent in plaintext body"""
        body_text = self._body_text(request) + " " + self._body_text(response)
        if not body_text or len(body_text) < 15:
            return []

        url = str(request.get("url", "")).lower()
        is_http = url.startswith("http://")
        severity = "CRITICAL" if is_http else "HIGH"

        findings = []

        # Strong, low false-positive patterns
        patterns = [
            (r'"(password|passwd|pwd)"\s*:\s*["\']([^"\']{6,})["\']', "Password"),
            (r'"(secret|api_key|private_key|auth_token|access_token|refresh_token)"\s*:\s*["\']([^"\']{8,})["\']', "Secret/Key"),
            (r'"(credit_card|cc_number|card_number|cvv)"\s*:\s*["\']([^"\']{12,})["\']', "Credit Card"),
            (r'"(ssn|social_security|aadhaar|pan|passport)"\s*:\s*["\']([^"\']{8,})["\']', "PII"),
            (r'"(private_key|rsa_private|key)"\s*:\s*["\']-----BEGIN', "Private Key"),
        ]

        for pattern, data_type in patterns:
            match = re.search(pattern, body_text, re.I)
            if match:
                exposed_value = match.group(2)[:30] + "..." if len(match.group(2)) > 30 else match.group(2)
                findings.append(_finding(
                    f"Plaintext {data_type} in Body",
                    f"Sensitive {data_type.lower()} sent in plaintext: {exposed_value}",
                    severity,
                    "Data Protection",
                    recommendation="Never send credentials in plaintext. Use secure hashing, tokenization, or encrypted fields.",
                    owasp="API3:2023",
                    cwe="CWE-312"
                ))

        # Generic secret-like values in JSON (fallback)
        if not findings and re.search(r'"(key|token|secret|password)"\s*:\s*["\'][^"\']{10,}', body_text, re.I):
            findings.append(_finding(
                "Plaintext Sensitive Value in Body",
                "Potential credential or secret detected in request/response body",
                severity,
                "Data Protection",
                owasp="API3:2023",
                cwe="CWE-312"
            ))

        return findings

    def _check_token_exposure(self, request, response, *args):
        text = self._body_text(request) + " " + self._body_text(response)
        patterns = [
            r"sk_live_", r"ghp_", r"AKIA[0-9A-Z]{16}", r"ey[A-Za-z0-9_-]{30,}",
            r"glpat-", r"xoxb-", r"sk_test_", r"sk-proj-", r"gsk_",
            r"AIza[0-9A-Za-z_-]{35}", r"AccountKey=", r"SK[0-9a-f]{32}"
        ]
        if any(re.search(p, text) for p in patterns):
            return [_finding("Hardcoded Secret/Token", "API key or secret exposed in payload", "CRITICAL", "Secret Exposure", cwe="CWE-312")]
        return []

    def _check_security_headers(self, request, response, is_test_host, *args):
        if is_test_host or not response:
            return []
        h = self._headers(response)
        important = ["strict-transport-security", "content-security-policy", "x-content-type-options",
                     "referrer-policy", "permissions-policy", "cross-origin-opener-policy"]
        missing = [x for x in important if x not in h]
        if missing:
            return [_finding("Missing Security Headers", f"Missing: {missing}", "MEDIUM", "Security Headers", owasp="API8:2023")]
        return []

    def _check_pii(self, request, response, *args):
        if not _presidio:
            text = self._body_text(request) + " " + self._body_text(response)
            if re.search(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text):
                return [_finding("PII Exposure - Email", "Email address detected in payload", "MEDIUM", "Data Protection")]
            return []
        return []

    def _check_rate_limiting(self, request, response, is_test_host, *args):
        if is_test_host or not response:
            return []
        h = self._headers(response)
        if not any("ratelimit" in k or "retry-after" in k for k in h):
            return [_finding("No Rate Limiting Indicators", "No rate limiting headers detected", "MEDIUM", "Availability", owasp="API4:2023")]
        return []

    def _check_injection(self, request, *args):
        text = self._body_text(request)
        if re.search(r"(union\s+select|xp_cmdshell|;\s*drop|;\s*shutdown|1\s*=\s*1|--\s*$)", text, re.I):
            return [_finding("SQL Injection Pattern", "Potential SQL injection detected", "CRITICAL", "Injection", owasp="API1:2023", cwe="CWE-89")]
        if re.search(r"(\.\./|\.\.\\|%2e%2e%2f)", text, re.I):
            return [_finding("Path Traversal Pattern", "Directory traversal attempt detected", "HIGH", "Injection")]
        return []

    def _check_sensitive_paths(self, request, *args):
        url = str(request.get("url", ""))
        if re.search(r"/(\.env|config\.json|database\.yml|credentials)", url, re.I):
            return [_finding("Highly Sensitive File Exposure", "Critical configuration file accessed", "CRITICAL", "Endpoint Exposure", owasp="API8:2023")]
        if re.search(r"/(admin|debug|actuator|swagger|metrics)", url, re.I) and not re.search(r"/(login|auth)", url, re.I):
            return [_finding("Sensitive Path Exposure", "Administrative/debug endpoint accessed", "HIGH", "Endpoint Exposure")]
        return []

    def _check_suspicious_payloads(self, request, *args):
        text = self._body_text(request)
        if re.search(r"(cmd\.exe|powershell\.exe|whoami|nc\s+-e|bash -i)", text, re.I):
            return [_finding("Suspicious/RCE Payload", "Potential remote command execution payload", "CRITICAL", "Malicious Payload")]
        return []

    def _check_response_leaks(self, request, response, *args):
        text = self._body_text(response)
        findings = []
        if re.search(r"(Traceback|Exception|NullPointerException|SyntaxError|mysql|postgres|sqlite).*error", text, re.I):
            findings.append(_finding("Stack Trace Exposure", "Server error details leaked", "HIGH", "Information Disclosure", owasp="API8:2023"))
        if re.search(r"\b(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)\d{1,3}\.\d{1,3}\b", text):
            findings.append(_finding("Internal IP Leakage", "Private IP address exposed", "MEDIUM", "Information Disclosure"))
        return findings

    def _check_idor_bola_indicators(self, request, response, *args):
        url = str(request.get("url", ""))
        if re.search(r"/(user|account|profile|order|document|file)/\d+", url) and not self._headers(request).get("authorization"):
            return [_finding("Potential IDOR/BOLA", "Object ID in URL without authentication", "HIGH", "Authorization", owasp="API1:2023")]
        return []

    def _check_excessive_data_exposure(self, request, response, *args):
        text = self._body_text(response)
        if re.search(r'"(password|secret|privateKey|token|ssn|credit_card)"', text):
            return [_finding("Excessive Data Exposure", "Sensitive fields returned in response", "HIGH", "Data Protection", owasp="API3:2023")]
        return []

    def _check_mass_assignment(self, request, *args):
        text = self._body_text(request)
        if re.search(r'"(isAdmin|role|permissions|balance|credits|userId)"', text, re.I):
            return [_finding("Mass Assignment Indicator", "Sensitive fields in request body", "MEDIUM", "Input Validation", owasp="API3:2023")]
        return []

    def _check_ssrf_indicators(self, request, *args):
        text = self._body_text(request)
        if re.search(r"(127\.0\.0\.1|localhost|169\.254\.169\.254|metadata\.google|file://|gopher://)", text, re.I):
            return [_finding("SSRF Payload Detected", "Server-Side Request Forgery indicators found", "CRITICAL", "Injection", owasp="API7:2023")]
        return []

    def _check_xxe_indicators(self, request, *args):
        text = self._body_text(request)
        if re.search(r"<!DOCTYPE|<!ENTITY|SYSTEM\s+[\"']", text, re.I):
            return [_finding("XXE Pattern Detected", "Potential XML External Entity attack", "HIGH", "Injection", cwe="CWE-611")]
        return []


# Singleton Instance
analyzer = TrustEdgeAnalyzer()
