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
        "__schema",
        "__type",
        "__typename",
        "introspectionquery"
    ]

    # =========================================================
    # SENSITIVE DATA
    # =========================================================

    SENSITIVE_FIELDS = [
        "password",
        "passwd",
        "token",
        "secret",
        "apikey",
        "api_key",
        "privatekey",
        "access_token",
        "refresh_token",
        "jwt",
        "session",
        "cookie",
        "creditcard",
        "cvv",
        "ssn",
        "bankaccount"
    ]

    # =========================================================
    # DANGEROUS MUTATIONS
    # =========================================================

    DANGEROUS_MUTATIONS = [
        "deleteuser",
        "dropdatabase",
        "removeadmin",
        "truncate",
        "resetpassword",
        "grantadmin",
        "deleteaccount"
    ]

    # =========================================================
    # SQLi
    # =========================================================

    SQLI_PATTERNS = [
        r"(\bor\b.*?=.*?)",
        r"union\s+select",
        r"drop\s+table",
        r"information_schema",
        r"--",
        r";",
        r"sleep\s*\(",
        r"benchmark\s*\(",
        r"insert\s+into",
        r"delete\s+from",
        r"update\s+.*?set",
    ]

    # =========================================================
    # NOSQLi
    # =========================================================

    NOSQL_PATTERNS = [
        r"\$ne",
        r"\$gt",
        r"\$regex",
        r"\$where",
        r"\$exists",
        r"\$or",
        r"\$and"
    ]

    # =========================================================
    # XSS
    # =========================================================

    XSS_PATTERNS = [
        r"<script.*?>",
        r"javascript:",
        r"onerror\s*=",
        r"onload\s*=",
        r"<img.*?>",
        r"<svg.*?>",
        r"alert\s*\(",
        r"document\.cookie"
    ]

    # =========================================================
    # SSRF
    # =========================================================

    SSRF_PATTERNS = [
        r"127\.0\.0\.1",
        r"localhost",
        r"0\.0\.0\.0",
        r"169\.254",
        r"file://",
        r"ftp://",
        r"internal",
        r"metadata"
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

        response_str = json.dumps(response_json).lower()

        # =====================================================
        # API1:2023 BROKEN OBJECT LEVEL AUTHORIZATION
        # =====================================================

        id_patterns = [
            r"user\s*\(\s*id:",
            r"account\s*\(\s*id:",
            r"admin\s*\(\s*id:"
        ]

        for pattern in id_patterns:

            if re.search(pattern, query, re.IGNORECASE):

                findings.append(
                    SecurityFinding(
                        severity=SeverityLevel.MEDIUM,
                        category="Authorization",
                        type="BOLA Risk",
                        title="Potential Object Level Authorization Risk",
                        message="Direct object reference detected.",
                        recommendation="Validate ownership checks server-side.",
                        impact="Unauthorized object access possible.",
                        owasp="API1:2023 Broken Object Level Authorization"
                    )
                )

                risk_score += 15
                break

        # =====================================================
        # API2:2023 BROKEN AUTHENTICATION
        # =====================================================

        auth = headers.get("Authorization", "").strip()

        if not auth:

            findings.append(
                SecurityFinding(
                    severity=SeverityLevel.HIGH,
                    category="Authentication",
                    type="Missing Authorization",
                    title="Authorization Header Missing",
                    message="GraphQL request without authorization.",
                    recommendation="Use JWT or OAuth2 authentication.",
                    impact="Unauthenticated access possible.",
                    owasp="API2:2023 Broken Authentication"
                )
            )

            risk_score += 20

        else:

            passed_checks.append("Authorization Header Present")

            # =================================================
            # JWT Validation
            # =================================================

            token = auth.replace("Bearer ", "").strip()

            if token.count(".") == 2:

                try:

                    token_parts = token.split(".")

                    padded_header = token_parts[0]

                    while len(padded_header) % 4 != 0:
                        padded_header += "="

                    header_data = json.loads(
                        base64.urlsafe_b64decode(
                            padded_header
                        ).decode()
                    )

                    alg = header_data.get("alg", "").lower()

                    if alg == "none":

                        findings.append(
                            SecurityFinding(
                                severity=SeverityLevel.CRITICAL,
                                category="JWT Security",
                                type="Weak JWT",
                                title="JWT Uses NONE Algorithm",
                                message="Insecure JWT algorithm detected.",
                                recommendation="Use HS256 or RS256.",
                                impact="JWT forgery possible.",
                                owasp="API2:2023 Broken Authentication"
                            )
                        )

                        risk_score += 40

                    else:

                        passed_checks.append("JWT Algorithm Validation Passed")

                except Exception:

                    findings.append(
                        SecurityFinding(
                            severity=SeverityLevel.MEDIUM,
                            category="JWT Security",
                            type="Malformed JWT",
                            title="Malformed JWT Detected",
                            message="JWT token format appears invalid.",
                            recommendation="Validate JWT structure.",
                            impact="Authentication bypass attempts possible.",
                            owasp="API2:2023 Broken Authentication"
                        )
                    )

                    risk_score += 10

        # =====================================================
        # API3:2023 SENSITIVE DATA EXPOSURE
        # =====================================================

        sensitive_found = False

        def extract_keys(data):

            keys = []

            if isinstance(data, dict):

                for k, v in data.items():

                    keys.append(str(k).lower())

                    keys.extend(extract_keys(v))

            elif isinstance(data, list):

                for item in data:

                    keys.extend(extract_keys(item))

            return keys

        response_keys = extract_keys(response_json)

        for field in GraphQLSecurityAnalyzer.SENSITIVE_FIELDS:

            if field.lower() in response_keys:

                sensitive_found = True

                findings.append(
                    SecurityFinding(
                        severity=SeverityLevel.CRITICAL,
                        category="Sensitive Data Exposure",
                        type="Sensitive Field Leakage",
                        title=f"Sensitive Data Exposed: {field}",
                        message=f"Detected sensitive field '{field}'.",
                        recommendation="Remove sensitive fields from responses.",
                        impact="Credential or PII exposure.",
                        owasp="API3:2023 Broken Object Property Level Authorization"
                    )
                )

                risk_score += 35

        if not sensitive_found:

            passed_checks.append("No Sensitive Data Exposure")

        # =====================================================
        # API4:2023 RESOURCE CONSUMPTION
        # =====================================================

        depth = GraphQLSecurityAnalyzer.calculate_depth(query)

        if depth > 8:

            findings.append(
                SecurityFinding(
                    severity=SeverityLevel.HIGH,
                    category="DOS Protection",
                    type="Deep Query",
                    title="Excessive Query Depth",
                    message=f"Detected query depth: {depth}",
                    recommendation="Apply GraphQL depth limiting.",
                    impact="Denial of service risk.",
                    owasp="API4:2023 Unrestricted Resource Consumption"
                )
            )

            risk_score += 20

        alias_count = len(re.findall(r"\w+\s*:", query))

        if alias_count > 20:

            findings.append(
                SecurityFinding(
                    severity=SeverityLevel.HIGH,
                    category="GraphQL Abuse",
                    type="Alias Overloading",
                    title="Excessive GraphQL Aliases",
                    message=f"Detected {alias_count} aliases.",
                    recommendation="Restrict alias counts.",
                    impact="Resource exhaustion possible.",
                    owasp="API4:2023 Unrestricted Resource Consumption"
                )
            )

            risk_score += 20

        if len(query) > 5000:

            findings.append(
                SecurityFinding(
                    severity=SeverityLevel.HIGH,
                    category="DOS Protection",
                    type="Large Payload",
                    title="Oversized Query",
                    message="Very large GraphQL query detected.",
                    recommendation="Limit query size.",
                    impact="Possible DOS attack.",
                    owasp="API4:2023 Unrestricted Resource Consumption"
                )
            )

            risk_score += 15

        # =====================================================
        # API5:2023 FUNCTION LEVEL AUTHORIZATION
        # =====================================================

        for mutation in GraphQLSecurityAnalyzer.DANGEROUS_MUTATIONS:

            if mutation in query_lower:

                findings.append(
                    SecurityFinding(
                        severity=SeverityLevel.HIGH,
                        category="Privilege Escalation",
                        type="Dangerous Mutation",
                        title=f"Dangerous Mutation Detected: {mutation}",
                        message=f"Mutation '{mutation}' detected.",
                        recommendation="Restrict admin mutations.",
                        impact="Privilege abuse possible.",
                        owasp="API5:2023 Broken Function Level Authorization"
                    )
                )

                risk_score += 25

        # =====================================================
        # API6:2023 BUSINESS LOGIC ABUSE
        # =====================================================

        business_keywords = [
            "transfermoney",
            "withdraw",
            "payment",
            "invoice",
            "salary"
        ]

        for keyword in business_keywords:

            if keyword in query_lower:

                findings.append(
                    SecurityFinding(
                        severity=SeverityLevel.MEDIUM,
                        category="Business Logic Abuse",
                        type="Sensitive Business Flow",
                        title="Sensitive Business Function Accessed",
                        message=f"Detected operation '{keyword}'.",
                        recommendation="Apply RBAC and transaction validation.",
                        impact="Business abuse possible.",
                        owasp="API6:2023 Unrestricted Access to Sensitive Business Flows"
                    )
                )

                risk_score += 15

        # =====================================================
        # API7:2023 SSRF
        # =====================================================

        for pattern in GraphQLSecurityAnalyzer.SSRF_PATTERNS:

            if re.search(pattern, query, re.IGNORECASE):

                findings.append(
                    SecurityFinding(
                        severity=SeverityLevel.HIGH,
                        category="SSRF",
                        type="Server Side Request Forgery",
                        title="Potential SSRF Payload",
                        message="Internal resource access pattern detected.",
                        recommendation="Block internal network requests.",
                        impact="Internal infrastructure exposure possible.",
                        owasp="API7:2023 SSRF"
                    )
                )

                risk_score += 30
                break

        # =====================================================
        # API8:2023 SECURITY MISCONFIGURATION
        # =====================================================

        for keyword in GraphQLSecurityAnalyzer.INTROSPECTION_KEYWORDS:

            if keyword.lower() in query_lower:

                findings.append(
                    SecurityFinding(
                        severity=SeverityLevel.HIGH,
                        category="Security Misconfiguration",
                        type="Introspection Enabled",
                        title="GraphQL Introspection Enabled",
                        message="Schema enumeration detected.",
                        recommendation="Disable introspection in production.",
                        impact="Attackers can enumerate schema.",
                        owasp="API8:2023 Security Misconfiguration"
                    )
                )

                risk_score += 25
                break

        # =====================================================
        # API8:2023 SQL INJECTION
        # =====================================================

        for pattern in GraphQLSecurityAnalyzer.SQLI_PATTERNS:

            if re.search(pattern, query, re.IGNORECASE):

                findings.append(
                    SecurityFinding(
                        severity=SeverityLevel.CRITICAL,
                        category="Injection",
                        type="SQL Injection",
                        title="SQL Injection Payload Detected",
                        message="Potential SQL injection payload.",
                        recommendation="Use parameterized queries.",
                        impact="Database compromise possible.",
                        owasp="API8:2023 Injection"
                    )
                )

                risk_score += 40
                break

        # =====================================================
        # NOSQL INJECTION
        # =====================================================

        for pattern in GraphQLSecurityAnalyzer.NOSQL_PATTERNS:

            if re.search(pattern, query, re.IGNORECASE):

                findings.append(
                    SecurityFinding(
                        severity=SeverityLevel.HIGH,
                        category="Injection",
                        type="NoSQL Injection",
                        title="NoSQL Injection Payload Detected",
                        message="Potential NoSQL injection payload.",
                        recommendation="Validate all GraphQL inputs.",
                        impact="Database manipulation possible.",
                        owasp="API8:2023 Injection"
                    )
                )

                risk_score += 30
                break

        # =====================================================
        # XSS DETECTION
        # =====================================================

        for pattern in GraphQLSecurityAnalyzer.XSS_PATTERNS:

            if re.search(pattern, query, re.IGNORECASE):

                findings.append(
                    SecurityFinding(
                        severity=SeverityLevel.HIGH,
                        category="Cross Site Scripting",
                        type="XSS Payload",
                        title="Cross Site Scripting Payload Detected",
                        message="Potential XSS payload found.",
                        recommendation="Sanitize all user input.",
                        impact="Client-side compromise possible.",
                        owasp="API8:2023 Injection"
                    )
                )

                risk_score += 30
                break

        # =====================================================
        # API9:2023 INVENTORY MANAGEMENT
        # =====================================================

        deprecated_keywords = [
            "v1",
            "legacy",
            "oldapi"
        ]

        for keyword in deprecated_keywords:

            if keyword in query_lower:

                findings.append(
                    SecurityFinding(
                        severity=SeverityLevel.LOW,
                        category="Deprecated API",
                        type="Old Endpoint Usage",
                        title="Deprecated API Usage Detected",
                        message=f"Detected keyword '{keyword}'.",
                        recommendation="Remove unused or legacy endpoints.",
                        impact="Outdated APIs may contain vulnerabilities.",
                        owasp="API9:2023 Improper Inventory Management"
                    )
                )

                risk_score += 10
                break

        # =====================================================
        # API10:2023 UNSAFE API CONSUMPTION
        # =====================================================

        external_url_patterns = [
            r"https?://"
        ]

        for pattern in external_url_patterns:

            if re.search(pattern, query, re.IGNORECASE):

                findings.append(
                    SecurityFinding(
                        severity=SeverityLevel.MEDIUM,
                        category="Unsafe API Consumption",
                        type="External API Call",
                        title="External API Reference Detected",
                        message="Potential external API consumption detected.",
                        recommendation="Validate third-party API trust.",
                        impact="Third-party compromise risk.",
                        owasp="API10:2023 Unsafe Consumption of APIs"
                    )
                )

                risk_score += 15
                break

        # =====================================================
        # FINAL ANALYSIS
        # =====================================================

        risk_score = min(risk_score, 100)

        analysis = SecurityAnalysis(

            risk_score=risk_score,

            findings_count=len(findings),

            critical_count=len([
                f for f in findings
                if f.severity == SeverityLevel.CRITICAL
            ]),

            high_count=len([
                f for f in findings
                if f.severity == SeverityLevel.HIGH
            ]),

            medium_count=len([
                f for f in findings
                if f.severity == SeverityLevel.MEDIUM
            ]),

            low_count=len([
                f for f in findings
                if f.severity == SeverityLevel.LOW
            ]),

            passed_checks=passed_checks,

            failed_checks=[
                finding.title
                for finding in findings
            ]
        )

        return (
            risk_score,
            [f.dict() for f in findings],
            analysis.dict()
        )

    # =========================================================
    # QUERY DEPTH CALCULATOR
    # =========================================================

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
