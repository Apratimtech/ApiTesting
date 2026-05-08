import jwt
import json
import re
import os
import logging
from datetime import datetime
from typing import Dict, Any, List, Set
from presidio_analyzer import AnalyzerEngine

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s")
logger = logging.getLogger("TrustEdgeAnalyzer")

# Groq AI (Optional)
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
groq_client = None
if GROQ_API_KEY:
    try:
        from groq import Groq
        groq_client = Groq(api_key=GROQ_API_KEY)
        logger.info("✅ Groq AI enabled")
    except Exception as e:
        logger.warning(f"Groq init failed: {e}")

analyzer_engine = AnalyzerEngine()

class TrustEdgeAnalyzer:
    def analyze(self, payload: Dict) -> Dict:
        try:
            request = payload.get("request", {})
            response = payload.get("response", {})
            return self.analyze_full_packet(request, response)
        except Exception as e:
            logger.error(f"Analyzer failed: {e}", exc_info=True)
            return {
                "error": str(e),
                "findings": [],
                "overall_risk_score": 5,
                "severity": "MEDIUM",
                "summary": "Analysis failed"
            }

    def analyze_full_packet(self, request: Dict, response: Dict) -> Dict:
        findings: List[Dict] = []
        # Core Security Checks
        findings.extend(self._auth_analysis(request))
        findings.extend(self._sensitive_data_analysis(request.get("body"), response.get("body")))
        findings.extend(self._transport_security_analysis(request))
        findings.extend(self._headers_security_analysis(request.get("headers", {}), response.get("headers", {})))
        findings.extend(self._owasp_api_top10_analysis(request, response))
        findings.extend(self._response_security_analysis(response))
        findings.extend(self._body_content_analysis(request))

        # Deduplicate + Add Recommendations
        findings = self._deduplicate_findings(findings)
        overall_risk_score = self._calculate_risk_score(findings)
        severity = self._get_severity_label(overall_risk_score)

        return {
            "findings": findings,
            "overall_risk_score": overall_risk_score,
            "severity": severity,
            "timestamp": datetime.utcnow().isoformat(),
            "url": request.get("url"),
            "method": request.get("method"),
            "summary": f"{len(findings)} findings • Risk: {severity} ({overall_risk_score}/10)",
            "total_findings": len(findings)
        }

    def _deduplicate_findings(self, findings: List[Dict]) -> List[Dict]:
        """Remove duplicate findings and enrich with recommendations"""
        seen: Set[str] = set()
        unique_findings = []
        for f in findings:
            key = f"{f.get('issue', '')}|{f.get('category', '')}"
            if key not in seen:
                seen.add(key)
                f["recommendation"] = self._get_recommendation(f.get("issue", ""))
                unique_findings.append(f)
        return unique_findings

    def _get_recommendation(self, issue: str) -> str:
        recommendations = {
            "Missing Authentication": "Implement strong authentication (JWT, OAuth2, or API Keys) on all protected endpoints.",
            "Sensitive Data Exposure": "Avoid returning sensitive information. Use data masking, pagination, or field-level authorization.",
            "Insecure Transport": "Force HTTPS only. Enable HSTS header in production.",
            "Missing Important Security Headers": "Add security headers: Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options.",
            "Excessive Data Exposure": "Implement pagination, response filtering, and avoid returning full objects unnecessarily.",
            "Information Disclosure via Headers": "Remove or obscure Server and X-Powered-By headers in production.",
            "GraphQL Endpoint Detected": "Disable introspection in production and implement proper rate limiting and query complexity limits.",
            "Server Error Response": "Improve error handling. Never expose stack traces or internal details to clients.",
            "Hardcoded Secrets Exposure": "Never store secrets in code or return them in API responses. Use environment variables or secret managers.",
        }
        for key, rec in recommendations.items():
            if key.lower() in issue.lower():
                return rec
        return "Follow OWASP API Security Top 10 best practices and conduct regular security testing."

    def _auth_analysis(self, req: Dict) -> List[Dict]:
        findings = []
        headers = {k.lower(): str(v) for k, v in req.get("headers", {}).items()}
        auth = headers.get("authorization", "")
        if not auth and not any(k in headers for k in ["x-api-key", "apikey", "x-auth-token", "authorization"]):
            findings.append({
                "issue": "Missing Authentication (OWASP API2)",
                "description": "No authentication mechanism detected. This endpoint is publicly accessible - critical risk.",
                "severity": 10,
                "category": "Authentication"
            })
        if "bearer" in auth.lower():
            try:
                token = auth.split(" ", 1)[1].strip()
                decoded = jwt.decode(token, options={"verify_signature": False})
                if "exp" not in decoded:
                    findings.append({
                        "issue": "JWT Missing Expiration (exp) Claim",
                        "description": "JWT token does not have expiration time. Risk of indefinite access.",
                        "severity": 8,
                        "category": "Authentication"
                    })
            except Exception:
                findings.append({
                    "issue": "Invalid or Malformed JWT",
                    "description": "JWT token could not be parsed properly.",
                    "severity": 7,
                    "category": "Authentication"
                })
        return findings

    def _sensitive_data_analysis(self, req_body: Any, res_body: Any) -> List[Dict]:
        findings = []
        for body, location in [(req_body, "Request"), (res_body, "Response")]:
            if not body:
                continue
            try:
                text = json.dumps(body) if isinstance(body, (dict, list)) else str(body)
                results = analyzer_engine.analyze(text=text, language="en")
                detected_types: Set[str] = set()
                for result in results:
                    if result.score > 0.65 and result.entity_type not in detected_types:
                        detected_types.add(result.entity_type)
                        findings.append({
                            "issue": f"Sensitive Data Exposure: {result.entity_type}",
                            "description": f"Detected {result.entity_type} in {location} body. This violates data protection best practices.",
                            "severity": 9,
                            "category": "Data Protection"
                        })
                # Hardcoded secrets detection
                if re.search(r'(?i)(api[_-]?key|secret|password|token)[\s:=]+["\']?([A-Za-z0-9._~+/-]{20,})', text):
                    findings.append({
                        "issue": "Hardcoded Secrets Exposure",
                        "description": "Potential API keys, passwords or tokens found in the body.",
                        "severity": 9,
                        "category": "Data Protection"
                    })
            except:
                pass
        return findings

    def _transport_security_analysis(self, req: Dict) -> List[Dict]:
        findings = []
        url = str(req.get("url", "")).strip()
        if url and not url.startswith("https"):
            findings.append({
                "issue": "Insecure Transport (HTTP instead of HTTPS)",
                "description": "API is using unencrypted HTTP. All data can be intercepted by attackers.",
                "severity": 9,
                "category": "Transport Security"
            })
        return findings

    def _headers_security_analysis(self, req_headers: Dict, res_headers: Dict) -> List[Dict]:
        findings = []
        lower_res = {k.lower(): str(v) for k, v in res_headers.items()}
        security_headers = ["content-security-policy", "strict-transport-security", "x-content-type-options", "x-frame-options"]
        missing = [h for h in security_headers if h not in lower_res]
        if missing:
            findings.append({
                "issue": "Missing Important Security Headers",
                "description": f"Missing: {', '.join(missing)}. These headers protect against XSS, clickjacking and MIME sniffing.",
                "severity": 6,
                "category": "Security Headers"
            })
        if "server" in lower_res or "x-powered-by" in lower_res:
            findings.append({
                "issue": "Information Disclosure via Headers",
                "description": "Server version or technology stack is exposed.",
                "severity": 5,
                "category": "Info Leak"
            })
        return findings

    def _body_content_analysis(self, request: Dict) -> List[Dict]:
        findings = []
        body_type = request.get("bodyType")
        if body_type == "graphql":
            findings.append({
                "issue": "GraphQL Endpoint Detected",
                "description": "GraphQL can be vulnerable to introspection and complex query attacks if not properly secured.",
                "severity": 4,
                "category": "API Design"
            })
        elif body_type in ["html", "javascript"]:
            findings.append({
                "issue": f"{body_type.upper()} Body Type Detected",
                "description": f"Using {body_type.upper()} as request body. Ensure proper Content-Type header is set.",
                "severity": 3,
                "category": "API Design"
            })
        return findings

    def _owasp_api_top10_analysis(self, request: Dict, response: Dict) -> List[Dict]:
        findings = []
        body_str = str(response.get("body", ""))
        if response.get("status") == 200 and len(body_str) > 100000:
            findings.append({
                "issue": "Excessive Data Exposure (OWASP API3)",
                "description": "Large response body returned. Consider implementing pagination and selective field return.",
                "severity": 7,
                "category": "Data Exposure"
            })
        return findings

    def _response_security_analysis(self, response: Dict) -> List[Dict]:
        findings = []
        if response.get("status") in [500, 502, 503]:
            findings.append({
                "issue": "Server Error Response",
                "description": "Server returned error status. May leak internal information.",
                "severity": 6,
                "category": "Error Handling"
            })
        return findings

    def _calculate_risk_score(self, findings: List[Dict]) -> int:
        if not findings:
            return 0
        total = sum(f.get("severity", 5) for f in findings)
        return min(10, round(total / len(findings)))

    def _get_severity_label(self, score: int) -> str:
        if score >= 9: return "CRITICAL"
        if score >= 7: return "HIGH"
        if score >= 5: return "MEDIUM"
        return "LOW"

# Singleton instance
analyzer = TrustEdgeAnalyzer()
