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

# -----------------------------
# PRODUCTION LOGGING
# -----------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("TrustEdgeAnalyzer")

# -----------------------------
# GROQ AI (Optional but Powerful)
# -----------------------------
GROQ_API_KEY: Optional[str] = os.getenv("GROQ_API_KEY")
groq_client = None
if GROQ_API_KEY:
    try:
        from groq import Groq
        groq_client = Groq(api_key=GROQ_API_KEY)
        logger.info("✅ Groq AI initialized - AI suggestions enabled")
    except Exception as e:
        logger.warning(f"Groq init failed: {e}")
else:
    logger.warning("GROQ_API_KEY not set → AI suggestions disabled")

# -----------------------------
# PRESIDIO + CUSTOM PATTERNS
# -----------------------------
analyzer = AnalyzerEngine()

# -----------------------------
# MAIN ANALYZER CLASS - Production Grade
# -----------------------------
class TrustEdgeAnalyzer:
    def analyze_full_packet(self, request: Dict, response: Dict) -> Dict:
        findings: List[Dict] = []

        try:
            # === MULTI-LAYER SECURITY ANALYSIS (OWASP API Top 10 Inspired) ===
            findings.extend(self._auth_analysis(request))                    # Broken Auth
            findings.extend(self._sensitive_data_analysis(request.get("body")))  # Sensitive Data Exposure
            findings.extend(self._transport_security_analysis(request))      # Insecure Transport
            findings.extend(self._headers_security_analysis(request.get("headers", {})))
            findings.extend(self._misc_owasp_analysis(request))              # Misc (BOLA hints, large payloads, etc.)

            overall_risk_score = self._calculate_risk_score(findings)
            severity = self._get_severity_label(overall_risk_score)

            ai_suggestions = self._get_ai_suggestions(findings, request)

            return {
                "findings": findings,
                "overall_risk_score": overall_risk_score,
                "severity": severity,
                "ai_suggestions": ai_suggestions,
                "timestamp": datetime.utcnow().isoformat(),
                "summary": f"Analyzed request • {len(findings)} findings • Risk: {severity} ({overall_risk_score}/10)"
            }

        except Exception as e:
            logger.error(f"Critical analysis failure: {e}", exc_info=True)
            return {
                "error": "Analysis engine failed",
                "details": str(e),
                "overall_risk_score": 5,
                "severity": "MEDIUM",
                "findings": []
            }

    # ------------------- AUTH ANALYSIS (JWT + more) -------------------
    def _auth_analysis(self, req: Dict) -> List[Dict]:
        findings = []
        headers = {k.lower(): str(v) for k, v in req.get("headers", {}).items()}

        auth = headers.get("authorization", "")
        has_api_key = any(k in headers for k in ["x-api-key", "apikey", "x-auth-token"])

        if not auth and not has_api_key:
            findings.append({
                "issue": "Missing Authentication",
                "description": "No Authorization header or API key found. Violates OWASP API2:2023 - Broken Authentication.",
                "severity": 10,
                "category": "Authentication"
            })

        if "bearer" in auth.lower():
            try:
                token = auth.split(" ", 1)[1].strip()
                # Decode without signature first for inspection
                decoded = jwt.decode(token, options={"verify_signature": False})

                if "exp" not in decoded:
                    findings.append({"issue": "JWT Missing 'exp' Claim", "severity": 8, "category": "Authentication"})
                elif datetime.utcfromtimestamp(decoded["exp"]) < datetime.utcnow():
                    findings.append({"issue": "JWT Token Expired", "severity": 9, "category": "Authentication"})

                if decoded.get("alg") == "none":
                    findings.append({"issue": "JWT 'none' Algorithm (Critical)", "severity": 10, "category": "Authentication"})

                if not decoded.get("iss"):
                    findings.append({"issue": "JWT Missing 'iss' (Issuer) Claim", "severity": 6, "category": "Authentication"})

            except (jwt_exc.DecodeError, jwt_exc.InvalidTokenError):
                findings.append({"issue": "Malformed or Invalid JWT", "severity": 7, "category": "Authentication"})
            except Exception as e:
                logger.warning(f"JWT parsing error: {e}")

        return findings

    # ------------------- SENSITIVE DATA (PII + Secrets) -------------------
    def _sensitive_data_analysis(self, body: Any) -> List[Dict]:
        findings = []
        if not body:
            return findings

        try:
            text = json.dumps(body) if isinstance(body, (dict, list)) else str(body)

            # Presidio PII
            results = analyzer.analyze(text=text, language="en")
            for result in results:
                if result.score > 0.65:
                    findings.append({
                        "issue": f"Sensitive Data: {result.entity_type}",
                        "description": f"Potential PII leakage detected in request body ({result.entity_type}).",
                        "severity": 9,
                        "category": "Data Exposure"
                    })

            # Strong secret patterns (inspired by Postman + OWASP)
            secret_patterns = [
                (r'(?i)(password|secret|private_key|api[-_]?key|auth[-_]?token)[:=]\s*["\']?([^\s"\'&<]{8,})', "Hard-coded Secret"),
                (r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+', "JWT Token in Body"),
                (r'(?i)(sk_live_|pk_live_|stripe)', "Stripe Secret/Key"),
            ]

            for pattern, issue in secret_patterns:
                if re.search(pattern, text):
                    findings.append({
                        "issue": issue,
                        "description": "Sensitive credential found in request body - high risk of exposure.",
                        "severity": 10,
                        "category": "Data Exposure"
                    })

        except Exception as e:
            logger.warning(f"Body analysis error: {e}")

        return findings

    # ------------------- TRANSPORT & NETWORK -------------------
    def _transport_security_analysis(self, req: Dict) -> List[Dict]:
        findings = []
        url = str(req.get("url", "")).strip()
        if not url:
            return findings

        if not url.startswith("https"):
            findings.append({
                "issue": "Insecure Transport (HTTP)",
                "description": "Request sent over plain HTTP - vulnerable to MITM attacks (OWASP API7).",
                "severity": 9,
                "category": "Transport"
            })

        parsed = urlparse(url)
        if re.search(r'(localhost|127\.0\.0\.1|::1|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)', parsed.netloc):
            findings.append({
                "issue": "Potential SSRF / Internal URL",
                "description": "URL may point to internal resources. Verify if user-controlled.",
                "severity": 7,
                "category": "Transport"
            })

        return findings

    # ------------------- HEADERS SECURITY -------------------
    def _headers_security_analysis(self, headers: Dict) -> List[Dict]:
        findings = []
        lower = {k.lower(): v for k, v in headers.items()}

        missing = [h for h in ["strict-transport-security", "content-security-policy", "x-content-type-options"] if h not in lower]
        if missing:
            findings.append({
                "issue": "Missing Security Headers",
                "description": f"Missing important headers: {', '.join(missing)}",
                "severity": 6,
                "category": "Configuration"
            })

        return findings

    # ------------------- MISC OWASP CHECKS -------------------
    def _misc_owasp_analysis(self, req: Dict) -> List[Dict]:
        findings = []
        body = req.get("body")
        if isinstance(body, (dict, list)):
            size = len(json.dumps(body))
            if size > 500_000:
                findings.append({
                    "issue": "Very Large Request Body",
                    "description": "Risk of resource exhaustion (OWASP API4: Unrestricted Resource Consumption)",
                    "severity": 5,
                    "category": "Configuration"
                })
        return findings

    # ------------------- RISK & SEVERITY -------------------
    def _calculate_risk_score(self, findings: List[Dict]) -> int:
        if not findings:
            return 0
        total = sum(f.get("severity", 5) for f in findings)
        score = total / len(findings)
        return min(10, max(0, round(score)))

    def _get_severity_label(self, score: int) -> str:
        if score >= 9: return "CRITICAL"
        if score >= 7: return "HIGH"
        if score >= 4: return "MEDIUM"
        return "LOW"

    # ------------------- AI SUGGESTIONS (Contextual) -------------------
    def _get_ai_suggestions(self, findings: List[Dict], request: Dict) -> Dict:
        if not groq_client:
            return {"raw": "AI disabled (no GROQ_API_KEY)", "issue": "", "summary": "", "fix": ""}

        prompt = f"""You are a senior API Security Architect.
Analyze these findings from a real API request:

Findings: {json.dumps(findings, indent=2)}

Request: {request.get('method')} {request.get('url')}

Provide clear, actionable advice in this exact JSON format:
{{
  "issue": "High-level summary",
  "summary": "Brief explanation of risks",
  "fix": "Concrete production-ready fixes (code examples if possible)"
}}
Be concise and prioritize highest severity issues."""

        try:
            chat = groq_client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2,
                max_tokens=700
            )
            content = chat.choices[0].message.content.strip()
            try:
                return json.loads(content)
            except:
                return {"raw": content, "issue": "", "summary": "", "fix": ""}
        except Exception as e:
            logger.error(f"AI failed: {e}")
            return {"raw": "AI suggestion unavailable", "issue": "", "summary": "", "fix": ""}


# Global instance used by main.py
analyzer = TrustEdgeAnalyzer()
