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

_SEVERITY_WEIGHT = {"CRITICAL": 10, "HIGH": 6, "MEDIUM": 3, "LOW": 1}

_STRONG_ALGS = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256"}
_ACCEPTABLE_ALGS = _STRONG_ALGS | {"HS256"}

_MAX_BODY_LEN = 80000

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

            findings = self._analyze_packet(request, response, is_test_host)

            if _groq_client and findings:
                ai = self._groq_enhance(request, findings)
                if ai:
                    findings.append(ai)

            findings = self._deduplicate(findings)
            risk = self._risk_score(findings)

            return {
                "success": True,
                "generated_by": "Trust_Edge Analyzer v2.4",
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

    def _analyze_packet(self, request: Dict, response: Dict, is_test_host: bool) -> List[Dict]:
        findings = []
        findings += self._check_transport_security(request)
        findings += self._check_authentication(request)
        findings += self._check_bearer_token(request)
        findings += self._check_jwt_detailed(request)
        findings += self._check_security_headers(response, is_test_host)
        findings += self._check_plaintext_credentials(request, response)
        findings += self._check_pii(request, response)
        findings += self._check_rate_limiting(response, is_test_host)
        findings += self._check_injection(request)
        findings += self._check_token_exposure(request, response)
        findings += self._check_sensitive_paths(request)
        findings += self._check_suspicious_payloads(request)
        return findings

    def _groq_enhance(self, request, findings):
        try:
            prompt = f"API Security Insight: URL {request.get('url')} | Findings: {[f['issue'] for f in findings]}"
            resp = _groq_client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=100
            )
            return _finding("AI Security Insight", resp.choices[0].message.content[:200], "MEDIUM", "AI Analysis")
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
        return [f for f in findings if (k := f"{f['issue']}|{f['category']}") not in seen and not seen.add(k)]

    def _risk_score(self, findings):
        raw = sum(_SEVERITY_WEIGHT.get(f.get("severity"), 0) for f in findings)
        score = round(100 * (1 - math.exp(-0.07 * raw)))
        highest = max(findings, key=lambda f: _SEVERITY_WEIGHT.get(f.get("severity"), 0), default={"severity": "LOW"})
        return {"score": score, "highest": highest["severity"]}

    # ==================== SECURITY CHECKS ====================

    def _check_transport_security(self, request):
        """Plain HTTP detection"""
        if str(request.get("url", "")).lower().startswith("http://"):
            return [_finding("Insecure HTTP", "Data sent unencrypted", "CRITICAL", "Transport Security", owasp="API8:2023", cwe="CWE-319")]
        return []

    def _check_authentication(self, request):
        """Missing authentication check"""
        headers = self._headers(request)
        if not any(headers.get(x) for x in ["authorization", "x-api-key", "cookie"]):
            return [_finding("No Authentication", "No auth mechanism found", "CRITICAL", "Authentication", owasp="API2:2023", cwe="CWE-306")]
        return []

    def _check_bearer_token(self, request):
        """Bearer token basic validation"""
        auth = self._headers(request).get("authorization", "")
        if not auth.lower().startswith("bearer "): 
            return []
        token = auth[7:].strip()
        findings = [_finding("Bearer Token Used", "Bearer authentication detected", "LOW", "Authentication")]
        if len(token) < 20:
            findings.append(_finding("Weak Bearer Token", "Token too short", "HIGH", "Authentication"))
        return findings

    def _check_jwt_detailed(self, request):
        """Deep JWT analysis with expiry and claims"""
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
                findings.append(_finding(f"Weak JWT Algorithm: {alg}", "", "HIGH", "JWT Security"))

            # Expiry check
            exp = payload.get("exp")
            if exp:
                if datetime.fromtimestamp(exp, tz=timezone.utc) < datetime.now(timezone.utc) - timedelta(minutes=5):
                    findings.append(_finding("JWT Expired", "", "HIGH", "JWT Security", cwe="CWE-613"))
            else:
                findings.append(_finding("JWT Missing exp claim", "Token never expires", "MEDIUM", "JWT Security", cwe="CWE-613"))

            if not payload.get("aud"):
                findings.append(_finding("JWT Missing aud claim", "Weak audience validation", "MEDIUM", "JWT Security"))
        except Exception as e:
            findings.append(_finding("JWT Parse Error", str(e)[:100], "MEDIUM", "JWT Security"))
        return findings

    def _check_plaintext_credentials(self, request, response):
        """Plain text password/secret detection in body"""
        text = self._body_text(request) + " " + self._body_text(response)
        if re.search(r'"password"\s*:\s*"[^"]{6,}"', text, re.I) or re.search(r'"secret"\s*:\s*"[^"]{8,}"', text, re.I):
            return [_finding("Plaintext Credential in Body", "Sensitive data exposed in plain text", "CRITICAL", "Data Protection", owasp="API3:2023", cwe="CWE-312")]
        return []

    def _check_token_exposure(self, request, response):
        """Signature-based secret detection"""
        text = self._body_text(request) + " " + self._body_text(response)
        if re.search(r"sk_live_|ghp_|AKIA[0-9A-Z]{16}|ey[A-Za-z0-9_-]{30,}", text):
            return [_finding("Hardcoded Secret/Token", "API key or token exposed in payload", "CRITICAL", "Secret Exposure", cwe="CWE-312")]
        return []

    def _check_security_headers(self, response, is_test_host):
        """Security headers check"""
        if is_test_host or not response: 
            return []
        h = self._headers(response)
        missing = [x for x in ["strict-transport-security", "x-content-type-options"] if x not in h]
        if missing:
            return [_finding("Missing Security Headers", f"Missing: {missing}", "MEDIUM", "Security Headers", owasp="API8:2023")]
        return []

    def _check_pii(self, request, response):
        if not _presidio: 
            return []
        return []

    def _check_rate_limiting(self, response, is_test_host):
        """Rate limiting headers"""
        if is_test_host or not response: 
            return []
        if not any("ratelimit" in k or "retry-after" in k for k in self._headers(response)):
            return [_finding("No Rate Limiting", "No rate limit headers detected", "MEDIUM", "Availability", owasp="API4:2023")]
        return []

    def _check_injection(self, request):
        """Injection pattern detection"""
        text = self._body_text(request)
        if re.search(r"(\.\./|union\s+select|xp_cmdshell|;|\bor\b\s+1=1)", text, re.I):
            return [_finding("Injection Pattern Detected", "Possible SQL/Command injection", "CRITICAL", "Injection", owasp="API1:2023", cwe="CWE-89")]
        return []

    def _check_sensitive_paths(self, request):
        """Sensitive URL paths"""
        if re.search(r"/(\.env|admin|debug|config|swagger|actuator)", str(request.get("url", "")), re.I):
            return [_finding("Sensitive Path Exposure", "Admin/debug/config endpoint", "HIGH", "Endpoint Exposure", owasp="API8:2023")]
        return []

    def _check_suspicious_payloads(self, request):
        """RCE / malicious payload detection"""
        if re.search(r"(cmd\.exe|powershell|whoami|nc\s+-e)", self._body_text(request), re.I):
            return [_finding("Suspicious/RCE Payload", "Potential command injection", "CRITICAL", "Malicious Payload")]
        return []


# Singleton Instance
analyzer = TrustEdgeAnalyzer()
