import re
import json
import hashlib
from datetime import datetime
from typing import Dict, List, Any


class SecurityAnalyzer:

    def __init__(self):

        self.sql_patterns = [
            r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
            r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
            r"w*((\%27)|(\'))((\%6F)|o|(\%4F))",
            r"(union(\s)+select)",
            r"(drop(\s)+table)",
            r"(or(\s)+1=1)",
            r"(sleep\()",
            r"(benchmark\()",
        ]

        self.xss_patterns = [
            r"<script.*?>.*?</script>",
            r"javascript:",
            r"onerror=",
            r"onload=",
            r"<iframe",
            r"<svg",
            r"document\.cookie",
        ]

        self.command_injection_patterns = [
            r"(;|\|\|)\s*(ls|cat|rm|wget|curl|bash)",
            r"`.*?`",
            r"\$\(.*?\)",
        ]

        self.path_traversal_patterns = [
            r"\.\./",
            r"\.\.\\",
            r"/etc/passwd",
            r"boot.ini",
        ]

        self.jwt_pattern = r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"

        self.secret_keywords = [
            "password",
            "secret",
            "api_key",
            "token",
            "access_key",
            "private_key",
        ]

    # =====================================================
    # MAIN ANALYZER
    # =====================================================

    def analyze(self, payload: Dict[str, Any]) -> Dict[str, Any]:

        findings: List[Dict[str, Any]] = []

        text = json.dumps(payload, default=str)

        findings.extend(
            self.detect_sql_injection(text)
        )

        findings.extend(
            self.detect_xss(text)
        )

        findings.extend(
            self.detect_command_injection(text)
        )

        findings.extend(
            self.detect_path_traversal(text)
        )

        findings.extend(
            self.detect_jwt_exposure(text)
        )

        findings.extend(
            self.detect_sensitive_data(payload)
        )

        findings.extend(
            self.detect_large_payload(text)
        )

        findings.extend(
            self.detect_suspicious_headers(payload)
        )

        risk_score = self.calculate_risk_score(
            findings
        )

        return {
            "timestamp": datetime.utcnow().isoformat(),
            "safe": risk_score < 50,
            "risk_score": risk_score,
            "total_findings": len(findings),
            "findings": findings,
            "payload_hash": hashlib.sha256(
                text.encode()
            ).hexdigest(),
            "security_grade": self.security_grade(
                risk_score
            ),
        }

    # =====================================================
    # SQL INJECTION
    # =====================================================

    def detect_sql_injection(
        self,
        text: str
    ) -> List[Dict]:

        findings = []

        for pattern in self.sql_patterns:

            if re.search(
                pattern,
                text,
                re.IGNORECASE
            ):

                findings.append({
                    "severity": "CRITICAL",
                    "issue": "SQL Injection Attempt",
                    "owasp": "A03:2021 - Injection",
                })

        return findings

    # =====================================================
    # XSS
    # =====================================================

    def detect_xss(
        self,
        text: str
    ) -> List[Dict]:

        findings = []

        for pattern in self.xss_patterns:

            if re.search(
                pattern,
                text,
                re.IGNORECASE
            ):

                findings.append({
                    "severity": "HIGH",
                    "issue": "Cross-Site Scripting Payload",
                    "owasp": "A03:2021 - Injection",
                })

        return findings

    # =====================================================
    # COMMAND INJECTION
    # =====================================================

    def detect_command_injection(
        self,
        text: str
    ) -> List[Dict]:

        findings = []

        for pattern in self.command_injection_patterns:

            if re.search(
                pattern,
                text,
                re.IGNORECASE
            ):

                findings.append({
                    "severity": "CRITICAL",
                    "issue": "Command Injection Attempt",
                    "owasp": "A03:2021 - Injection",
                })

        return findings

    # =====================================================
    # PATH TRAVERSAL
    # =====================================================

    def detect_path_traversal(
        self,
        text: str
    ) -> List[Dict]:

        findings = []

        for pattern in self.path_traversal_patterns:

            if re.search(
                pattern,
                text,
                re.IGNORECASE
            ):

                findings.append({
                    "severity": "HIGH",
                    "issue": "Path Traversal Attempt",
                    "owasp": "A01:2021 - Broken Access Control",
                })

        return findings

    # =====================================================
    # JWT EXPOSURE
    # =====================================================

    def detect_jwt_exposure(
        self,
        text: str
    ) -> List[Dict]:

        findings = []

        if re.search(self.jwt_pattern, text):

            findings.append({
                "severity": "MEDIUM",
                "issue": "JWT Token Exposure",
                "owasp": "A02:2021 - Cryptographic Failures",
            })

        return findings

    # =====================================================
    # SECRET DETECTION
    # =====================================================

    def detect_sensitive_data(
        self,
        payload: Dict
    ) -> List[Dict]:

        findings = []

        payload_text = json.dumps(payload).lower()

        for keyword in self.secret_keywords:

            if keyword in payload_text:

                findings.append({
                    "severity": "MEDIUM",
                    "issue": f"Sensitive Data Exposure ({keyword})",
                    "owasp": "A02:2021 - Cryptographic Failures",
                })

        return findings

    # =====================================================
    # LARGE PAYLOAD
    # =====================================================

    def detect_large_payload(
        self,
        text: str
    ) -> List[Dict]:

        findings = []

        if len(text) > 100000:

            findings.append({
                "severity": "HIGH",
                "issue": "Potential DoS Payload",
                "owasp": "A04:2021 - Insecure Design",
            })

        return findings

    # =====================================================
    # SUSPICIOUS HEADERS
    # =====================================================

    def detect_suspicious_headers(
        self,
        payload: Dict
    ) -> List[Dict]:

        findings = []

        suspicious_headers = [
            "x-forwarded-for",
            "x-real-ip",
            "cf-connecting-ip",
        ]

        payload_text = json.dumps(payload).lower()

        for header in suspicious_headers:

            if header in payload_text:

                findings.append({
                    "severity": "LOW",
                    "issue": f"Spoofable Header Detected ({header})",
                    "owasp": "A09:2021 - Security Logging Failures",
                })

        return findings

    # =====================================================
    # RISK SCORE
    # =====================================================

    def calculate_risk_score(
        self,
        findings: List[Dict]
    ) -> int:

        score = 0

        for finding in findings:

            severity = finding["severity"]

            if severity == "CRITICAL":
                score += 35

            elif severity == "HIGH":
                score += 25

            elif severity == "MEDIUM":
                score += 15

            elif severity == "LOW":
                score += 5

        return min(score, 100)

    # =====================================================
    # SECURITY GRADE
    # =====================================================

    def security_grade(
        self,
        risk_score: int
    ) -> str:

        if risk_score >= 90:
            return "F"

        if risk_score >= 75:
            return "D"

        if risk_score >= 50:
            return "C"

        if risk_score >= 25:
            return "B"

        return "A"


# =========================================================
# SINGLETON INSTANCE
# =========================================================

analyzer = SecurityAnalyzer()
