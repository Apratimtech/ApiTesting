import jwt
import json
import re
import os
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
from presidio_analyzer import AnalyzerEngine
import jwt.exceptions as jwt_exc

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s")
logger = logging.getLogger("TrustEdgeAnalyzer")

# Groq (optional)
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
            return {"error": str(e), "findings": [], "overall_risk_score": 5, "severity": "MEDIUM"}

    def analyze_full_packet(self, request: Dict, response: Dict) -> Dict:
        findings: List[Dict] = []

        findings.extend(self._auth_analysis(request))
        findings.extend(self._sensitive_data_analysis(request.get("body"), response.get("body")))
        findings.extend(self._transport_security_analysis(request))
        findings.extend(self._headers_security_analysis(request.get("headers", {}), response.get("headers", {})))
        findings.extend(self._owasp_api_top10_analysis(request, response))
        findings.extend(self._response_security_analysis(response))

        overall_risk_score = self._calculate_risk_score(findings)
        severity = self._get_severity_label(overall_risk_score)
        ai_suggestions = self._get_ai_suggestions(findings, request)

        return {
            "findings": findings,
            "overall_risk_score": overall_risk_score,
            "severity": severity,
            "ai_suggestions": ai_suggestions,
            "timestamp": datetime.utcnow().isoformat(),
            "summary": f"{len(findings)} findings • Risk: {severity} ({overall_risk_score}/10)",
        }

    def _auth_analysis(self, req: Dict) -> List[Dict]:
        findings = []
        headers = {k.lower(): str(v) for k, v in req.get("headers", {}).items()}
        auth = headers.get("authorization", "")

        if not auth and not any(k in headers for k in ["x-api-key", "apikey", "x-auth-token"]):
            findings.append({
                "issue": "Missing Authentication",
                "description": "No authentication mechanism detected. This is a critical risk (OWASP API2).",
                "severity": 10,
                "category": "Authentication"
            })

        if "bearer" in auth.lower():
            try:
                token = auth.split(" ", 1)[1].strip()
                decoded = jwt.decode(token, options={"verify_signature": False})
                if "exp" not in decoded:
                    findings.append({"issue": "JWT Missing Expiration (exp)", "severity": 8, "category": "Authentication"})
                elif datetime.utcfromtimestamp(decoded["exp"]) < datetime.utcnow():
                    findings.append({"issue": "JWT Token Expired", "severity": 9, "category": "Authentication"})
            except Exception:
                findings.append({"issue": "Invalid or Malformed JWT", "severity": 7, "category": "Authentication"})

        return findings

    def _sensitive_data_analysis(self, req_body: Any, res_body: Any) -> List[Dict]:
        findings = []
        for body in [req_body, res_body]:
            if not body:
                continue
            try:
                text = json.dumps(body) if isinstance(body, (dict, list)) else str(body)
                results = analyzer_engine.analyze(text=text, language="en")
                for result in results:
                    if result.score > 0.7:
                        findings.append({
                            "issue": f"Sensitive Data Exposure: {result.entity_type}",
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
            findings.append({"issue": "Insecure Transport (HTTP instead of HTTPS)", "severity": 9, "category": "Transport"})
        return findings

    def _headers_security_analysis(self, req_headers: Dict, res_headers: Dict) -> List[Dict]:
        findings = []
        lower_req = {k.lower(): v for k, v in req_headers.items()}
        lower_res = {k.lower(): v for k, v in res_headers.items()}

        security_headers = ["content-security-policy", "strict-transport-security", "x-content-type-options", "x-frame-options"]
        missing = [h for h in security_headers if h not in lower_res]

        if missing:
            findings.append({
                "issue": f"Missing Security Headers: {', '.join(missing)}",
                "severity": 6,
                "category": "Security Headers"
            })

        if "server" in lower_res or "x-powered-by" in lower_res:
            findings.append({"issue": "Information Disclosure via Headers", "severity": 5, "category": "Info Leak"})

        return findings

    def _owasp_api_top10_analysis(self, request: Dict, response: Dict) -> List[Dict]:
        findings = []
        # Add more checks here as you grow (rate limiting hint, large response, etc.)
        if response.get("status") == 200 and len(str(response.get("body", ""))) > 100000:
            findings.append({"issue": "Possible Excessive Data Exposure (OWASP API3)", "severity": 7, "category": "Data Exposure"})
        return findings

    def _response_security_analysis(self, response: Dict) -> List[Dict]:
        findings = []
        if response.get("status") in [500, 502, 503]:
            findings.append({"issue": "Server Error - Potential Information Leak", "severity": 6, "category": "Error Handling"})
        return findings

    def _calculate_risk_score(self, findings: List[Dict]) -> int:
        if not findings:
            return 0
        return min(10, round(sum(f.get("severity", 5) for f in findings) / len(findings)))

    def _get_severity_label(self, score: int) -> str:
        if score >= 9: return "CRITICAL"
        if score >= 7: return "HIGH"
        if score >= 4: return "MEDIUM"
        return "LOW"

    def _get_ai_suggestions(self, findings: List[Dict], request: Dict) -> Dict:
        if not groq_client:
            return {"status": "AI disabled - Set GROQ_API_KEY"}
        # You can expand this with proper prompt later
        return {"status": "AI suggestions coming soon..."}


analyzer = TrustEdgeAnalyzer()
