from typing import List, Dict, Any
import re
import json
import base64

from app.graphql.graphql_models import (
    SecurityFinding,
    SeverityLevel,
    SecurityAnalysis
)


class GraphQLSecurityAnalyzer:

    # =========================================================
    # GRAPHQL ENUMERATION
    # =========================================================

    INTROSPECTION_KEYWORDS = [
        "__schema", "__type", "__typename", "introspectionquery"
    ]

    FEDERATION_PATTERNS = [
        "_service", "_entities"
    ]

    # =========================================================
    # SENSITIVE DATA
    # =========================================================

    SENSITIVE_FIELDS = [
        "password", "passwd", "token", "secret", "apikey", "api_key",
        "privatekey", "access_token", "refresh_token", "jwt", "session",
        "cookie", "creditcard", "cvv", "ssn", "bankaccount"
    ]

    PII_PATTERNS = [
        r"\b\d{13,19}\b",                    # Credit cards
        r"\b\d{3}-\d{2}-\d{4}\b",            # SSN
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",  # Email
    ]

    SECRET_PATTERNS = [
        r"AKIA[0-9A-Z]{16}",
        r"ghp_[A-Za-z0-9]{36}",
        r"sk-[A-Za-z0-9]{20,}",
    ]

    # =========================================================
    # DANGEROUS MUTATIONS
    # =========================================================

    DANGEROUS_MUTATIONS = [
        "deleteuser", "dropdatabase", "removeadmin", "truncate",
        "resetpassword", "grantadmin", "deleteaccount"
    ]

    # =========================================================
    # INJECTION PATTERNS
    # =========================================================

    SQLI_PATTERNS = [
        r"'\s*or\s*'1'\s*=\s*'1",
        r"union\s+all\s+select",
        r"union\s+select",
        r"drop\s+table",
        r"information_schema",
        r"sleep\s*\(",
        r"benchmark\s*\(",
        r"xp_cmdshell",
        r"load_file\s*\(",
    ]

    NOSQL_PATTERNS = [
        r"\$ne", r"\$gt", r"\$regex", r"\$where", r"\$exists", r"\$or", r"\$and"
    ]

    XSS_PATTERNS = [
        r"<script.*?>", r"javascript:", r"onerror\s*=", r"onload\s*=",
        r"<img.*?>", r"<svg.*?>", r"alert\s*\(", r"document\.cookie"
    ]

    # =========================================================
    # MAIN ANALYZER
    # =========================================================

    @staticmethod
    def analyze(
        query: str,
        headers: Dict[str, str],
        response_json: Dict[str, Any]
    ) -> tuple[int, List[Dict[str, Any]], Dict[str, Any]]:

        findings: List[SecurityFinding] = []
        passed_checks: List[str] = []
        risk_score = 0

        query_lower = query.lower()

        # Safe JSON string conversion
        try:
            response_str = json.dumps(response_json).lower()
        except Exception:
            response_str = ""

        # =====================================================
        # Helper: Add Finding
        # =====================================================
        def add_finding(severity: SeverityLevel, category: str, title: str, message: str,
                       recommendation: str, impact: str, owasp: str = ""):
            nonlocal risk_score
            finding = SecurityFinding(
                severity=severity,
                category=category,
                type=title,           # ← Fixed: Required by model
                title=title,
                message=message,
                recommendation=recommendation,
                impact=impact,
                owasp=owasp
            )
            findings.append(finding)

            # Weighted scoring
            weights = {
                SeverityLevel.CRITICAL: 25,
                SeverityLevel.HIGH: 15,
                SeverityLevel.MEDIUM: 8,
                SeverityLevel.LOW: 3,
            }
            risk_score += weights.get(severity, 5)
            return finding

        # =====================================================
        # 1. BROKEN OBJECT LEVEL AUTHORIZATION (BOLA)
        # =====================================================
        id_patterns = [r"user\s*\(\s*id:", r"account\s*\(\s*id:", r"admin\s*\(\s*id:"]
        for pattern in id_patterns:
            if re.search(pattern, query, re.IGNORECASE):
                add_finding(
                    SeverityLevel.MEDIUM, "Authorization", "Potential Object Level Authorization Risk",
                    "Direct object reference detected.", "Validate ownership checks server-side.",
                    "Unauthorized object access possible.", "API1:2023"
                )
                break

        # =====================================================
        # 2. BROKEN AUTHENTICATION + JWT Analysis
        # =====================================================
        auth = headers.get("Authorization", "").strip()

        if not auth:
            add_finding(
                SeverityLevel.HIGH, "Authentication", "Authorization Header Missing",
                "GraphQL request without authorization.", "Use JWT or OAuth2 authentication.",
                "Unauthenticated access possible.", "API2:2023"
            )
        else:
            token = auth.replace("Bearer ", "").strip()
            if token.count(".") == 2:  # JWT
                try:
                    parts = token.split(".")
                    # Header
                    padded = parts[0] + "=" * ((4 - len(parts[0]) % 4) % 4)
                    header = json.loads(base64.urlsafe_b64decode(padded).decode())
                    alg = header.get("alg", "").lower()

                    WEAK_ALGS = ["none", "hs1", "md5"]
                    if alg in WEAK_ALGS:
                        add_finding(
                            SeverityLevel.CRITICAL, "JWT Security", "Weak JWT Algorithm",
                            f"JWT uses insecure algorithm: {alg}", "Use HS256 or RS256.",
                            "JWT forgery possible.", "API2:2023"
                        )

                    # Payload
                    padded_payload = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
                    payload = json.loads(base64.urlsafe_b64decode(padded_payload).decode())

                    if not payload.get("exp"):
                        add_finding(
                            SeverityLevel.HIGH, "JWT Security", "JWT Expiration Missing",
                            "JWT does not have expiration claim.", "Add 'exp' claim.",
                            "Token can be used indefinitely.", "API2:2023"
                        )
                    if not payload.get("iss"):
                        add_finding(
                            SeverityLevel.MEDIUM, "JWT Security", "JWT Issuer Missing",
                            "JWT does not have issuer claim.", "Add 'iss' claim.",
                            "Reduced trust verification.", "API2:2023"
                        )

                except Exception:
                    add_finding(
                        SeverityLevel.MEDIUM, "JWT Security", "Malformed JWT",
                        "JWT token format appears invalid.", "Validate JWT structure.",
                        "Authentication bypass attempts possible.", "API2:2023"
                    )

        # =====================================================
        # 3. SENSITIVE DATA EXPOSURE
        # =====================================================
        response_keys = GraphQLSecurityAnalyzer._extract_keys(response_json)

        for field in GraphQLSecurityAnalyzer.SENSITIVE_FIELDS:
            if field.lower() in response_keys:
                add_finding(
                    SeverityLevel.CRITICAL, "Data Protection", f"Sensitive Field Exposed: {field}",
                    f"Detected sensitive field '{field}'.", "Remove sensitive fields from responses.",
                    "Credential or PII exposure.", "API3:2023"
                )

        # PII & Secret patterns in response values
        for pattern in GraphQLSecurityAnalyzer.PII_PATTERNS + GraphQLSecurityAnalyzer.SECRET_PATTERNS:
            if re.search(pattern, response_str):
                add_finding(
                    SeverityLevel.CRITICAL, "Data Protection", "Sensitive Value in Response",
                    "Potential credential or secret detected in response body.",
                    "Mask or remove sensitive values from API responses.",
                    "Data leakage risk.", "API3:2023"
                )
                break

        # =====================================================
        # 4. RESOURCE CONSUMPTION / DOS PROTECTION
        # =====================================================
        depth = GraphQLSecurityAnalyzer.calculate_depth(query)
        alias_count = len(re.findall(r"\w+\s*:", query))

        if depth > 8:
            add_finding(
                SeverityLevel.HIGH, "DOS Protection", "Excessive Query Depth",
                f"Detected query depth: {depth}", "Apply GraphQL depth limiting.",
                "Denial of service risk.", "API4:2023"
            )

        if alias_count > 10 and depth > 5:
            add_finding(
                SeverityLevel.HIGH, "GraphQL Abuse", "Alias Overloading",
                f"Detected {alias_count} aliases in deep query.", "Restrict alias usage.",
                "Resource exhaustion possible.", "API4:2023"
            )

        if len(query) > 5000:
            add_finding(
                SeverityLevel.HIGH, "DOS Protection", "Oversized Query",
                "Very large GraphQL query detected.", "Limit query size.",
                "Possible DOS attack.", "API4:2023"
            )

        # Batching detection
        if query.count("{") > 15 or query.count("query") > 8:
            add_finding(
                SeverityLevel.HIGH, "DOS Protection", "GraphQL Batching Attack",
                "Multiple queries detected in single request.", "Implement batch size limits.",
                "Rate limit bypass possible.", "API4:2023"
            )

        # =====================================================
        # Other checks
        # =====================================================
        for keyword in GraphQLSecurityAnalyzer.INTROSPECTION_KEYWORDS + GraphQLSecurityAnalyzer.FEDERATION_PATTERNS:
            if keyword.lower() in query_lower:
                add_finding(
                    SeverityLevel.CRITICAL, "Security Misconfiguration", "Introspection / Federation Enabled",
                    "Schema enumeration or federation query detected.", "Disable introspection in production.",
                    "Attackers can enumerate schema.", "API8:2023"
                )
                break

        for pattern in GraphQLSecurityAnalyzer.SQLI_PATTERNS:
            if re.search(pattern, query, re.IGNORECASE):
                add_finding(
                    SeverityLevel.CRITICAL, "Injection", "SQL Injection Payload",
                    "Potential SQL injection payload.", "Use parameterized queries.",
                    "Database compromise possible.", "API8:2023"
                )
                break

        for pattern in GraphQLSecurityAnalyzer.NOSQL_PATTERNS:
            if re.search(pattern, query, re.IGNORECASE):
                add_finding(SeverityLevel.HIGH, "Injection", "NoSQL Injection",
                           "Potential NoSQL injection payload.", "Validate all inputs.",
                           "Database manipulation possible.", "API8:2023")
                break

        for pattern in GraphQLSecurityAnalyzer.XSS_PATTERNS:
            if re.search(pattern, query, re.IGNORECASE):
                add_finding(SeverityLevel.HIGH, "Cross Site Scripting", "XSS Payload",
                           "Potential XSS payload found.", "Sanitize all user input.",
                           "Client-side compromise possible.", "API8:2023")
                break

        SSRF_PATTERNS = [r"127\.0\.0\.1", r"localhost", r"file://", r"metadata"]
        for pattern in SSRF_PATTERNS:
            if re.search(pattern, query, re.IGNORECASE):
                add_finding(SeverityLevel.HIGH, "SSRF", "Potential SSRF Payload",
                           "Internal resource access pattern detected.", "Block internal requests.",
                           "Internal infrastructure exposure possible.", "API7:2023")
                break

        # =====================================================
        # FINAL SCORING
        # =====================================================
        risk_score = min(risk_score, 100)

        analysis = SecurityAnalysis(
            risk_score=risk_score,
            findings_count=len(findings),
            critical_count=len([f for f in findings if f.severity == SeverityLevel.CRITICAL]),
            high_count=len([f for f in findings if f.severity == SeverityLevel.HIGH]),
            medium_count=len([f for f in findings if f.severity == SeverityLevel.MEDIUM]),
            low_count=len([f for f in findings if f.severity == SeverityLevel.LOW]),
            passed_checks=passed_checks,
            failed_checks=[f.title for f in findings]
        )

        return risk_score, [f.dict() for f in findings], analysis.dict()

    @staticmethod
    def _extract_keys(data: Any) -> List[str]:
        keys = []
        if isinstance(data, dict):
            for k, v in data.items():
                keys.append(str(k).lower())
                keys.extend(GraphQLSecurityAnalyzer._extract_keys(v))
        elif isinstance(data, list):
            for item in data:
                keys.extend(GraphQLSecurityAnalyzer._extract_keys(item))
        return keys

    @staticmethod
    def calculate_depth(query: str) -> int:
        max_depth = 0
        current_depth = 0
        for char in query:
            if char == "{":
                current_depth += 1
                max_depth = max(max_depth, current_depth)
            elif char == "}":
                current_depth -= 1
        return max_depth
