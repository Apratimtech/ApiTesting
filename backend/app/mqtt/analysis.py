"""
MQTT Security Analysis Engine - OWASP Aligned + IoT Hardened
"""
import re
import time
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field


# ============ Data Classes ============
@dataclass
class SecurityFinding:
    severity: str
    title: str
    description: str
    cwe: Optional[str] = None
    owasp: Optional[str] = None


@dataclass
class AnalysisResult:
    success: bool
    message: str
    risk_score: int = 0
    latency: Optional[str] = None
    security_findings: List[Dict[str, Any]] = field(default_factory=list)


# ============ Security Analyzer ============
class MQTTSecurityAnalyzer:
    """Enterprise MQTT Security Analysis Engine - OWASP + IoT Focused"""

    def __init__(self):
        self.dangerous_topics = ["$sys", "#", "admin", "config", "password", "secret", "private", "root", "system"]

        # Enhanced IoT/MQTT-specific injection & command patterns
        self.injection_patterns = [
            r"\$\{[^}]+\}", r"{{[^}]+}}", r"<script", r"javascript:", r"on\w+\s*=",
            r"eval\s*\(", r"exec\s*\(",
            # Real IoT attack patterns
            r";\s*rm\s+-rf", r"\|\s*sh", r"wget\s+http", r"curl\s+http", r"nc\s+-e",
            r"bash\s+-i", r"powershell\s+-enc", r"sh\s+-c", r"bin/sh", r"/dev/tcp/",
        ]

        self.sensitive_patterns = [
            r'(?i)(password|api[_-]?key|secret|token|private[_-]?key|credential|auth)\s*[:=]\s*["\']?[^"\',\s]+',
            r'"password"\s*:\s*"[^"]+"',
            r'"api[_-]?key"\s*:\s*"[^"]+"',
        ]

        self.weak_passwords = ["password", "123456", "qwerty", "admin", "root", "user", "test", "demo", "letmein"]

        self.severity_weights = {
            "INFO": 0,
            "LOW": 5,
            "MEDIUM": 15,
            "HIGH": 25,
            "CRITICAL": 40,
        }

    def _measure_latency(self, start_time: float) -> str:
        return f"{round((time.perf_counter() - start_time) * 1000, 2)}ms"

    def _add_finding(self, findings: List, severity: str, title: str, description: str, cwe: str = "", owasp: str = ""):
        finding = SecurityFinding(
            severity=severity,
            title=title,
            description=description,
            cwe=cwe,
            owasp=owasp
        )
        findings.append(finding)

    def analyze_connect(self, data: Dict[str, Any]) -> AnalysisResult:
        start_time = time.perf_counter()
        findings = []
        risk_score = 0

        broker_host = data.get("broker_host", "")
        broker_port = data.get("broker_port", 1883)
        tls_enabled = data.get("tls_enabled", False)
        tls_insecure = data.get("tls_insecure", False)
        client_id = data.get("client_id", "")
        username = data.get("username", "")
        password = data.get("password", "")
        subscribe_topics = data.get("subscribe_topics", ["#"])
        qos = data.get("qos", 1)

        # Broker Host Validation
        if not broker_host or not broker_host.strip():
            self._add_finding(findings, "HIGH", "Missing Broker Host",
                              "Broker host is empty or not specified", cwe="CWE-284")
            risk_score += self.severity_weights["HIGH"]

        # TLS Checks
        if not tls_enabled:
            self._add_finding(findings, "HIGH", "Unencrypted Connection",
                              "Using unencrypted MQTT without TLS", cwe="CWE-319", owasp="I7")
            risk_score += self.severity_weights["HIGH"]
        elif tls_enabled and tls_insecure:
            self._add_finding(findings, "HIGH", "TLS Certificate Validation Disabled",
                              "Server certificate verification is disabled", cwe="CWE-295", owasp="I7")
            risk_score += self.severity_weights["HIGH"]

        # Port Security
        if broker_port == 1883:
            if tls_enabled:
                self._add_finding(findings, "MEDIUM", "TLS on Standard MQTT Port",
                                  "TLS enabled but using default non-TLS port 1883")
            else:
                self._add_finding(findings, "HIGH", "Plain MQTT Port",
                                  "Using standard unencrypted MQTT port 1883")

        # Authentication
        if not username and not password:
            self._add_finding(findings, "CRITICAL", "No Authentication",
                              "Anonymous access enabled", cwe="CWE-306", owasp="I3")
            risk_score += self.severity_weights["CRITICAL"]
        elif not username or not password:
            self._add_finding(findings, "HIGH", "Incomplete Authentication",
                              "Missing username or password", cwe="CWE-287")
            risk_score += self.severity_weights["HIGH"]
        else:
            if password.lower() in self.weak_passwords:
                self._add_finding(findings, "HIGH", "Weak Password Detected", 
                                  "Commonly used password", cwe="CWE-521")
                risk_score += self.severity_weights["HIGH"]
            elif len(password) < 8:
                self._add_finding(findings, "MEDIUM", "Short Password", 
                                  "Password is too short", cwe="CWE-521")
                risk_score += self.severity_weights["MEDIUM"]

        # Client ID Security
        if not client_id:
            self._add_finding(findings, "MEDIUM", "No Client ID Provided",
                              "Broker will auto-generate ID", cwe="CWE-284")
            risk_score += self.severity_weights["MEDIUM"]
        elif client_id.lower() in ["client", "mqtt", "test", "device", "sensor"] or client_id.endswith("123"):
            self._add_finding(findings, "MEDIUM", "Predictable Client ID",
                              "Using common or weak client ID", cwe="CWE-798")
            risk_score += self.severity_weights["MEDIUM"]
        elif len(client_id) < 6:
            self._add_finding(findings, "MEDIUM", "Short Client ID",
                              "Client ID is too short", cwe="CWE-284")
            risk_score += self.severity_weights["MEDIUM"]

        # QoS Analysis
        if qos == 0:
            self._add_finding(findings, "LOW", "QoS 0 Used",
                              "No delivery guarantee - messages may be lost")
        elif qos == 2:
            self._add_finding(findings, "INFO", "QoS 2 Used",
                              "Highest delivery guarantee enabled")

        # Subscription risks
        seen = set()
        for topic in subscribe_topics:
            if topic in seen: 
                continue
            seen.add(topic)

            if topic == "#" or topic.endswith("#"):
                self._add_finding(findings, "HIGH", "Overly Broad Subscription",
                                  "Wildcard # subscribes to all topics", cwe="CWE-732")
                risk_score += self.severity_weights["HIGH"]
            if topic.startswith("$SYS") or "$sys" in topic.lower():
                self._add_finding(findings, "HIGH", "System Topic Subscription",
                                  "Accessing internal broker topics", cwe="CWE-200")
                risk_score += self.severity_weights["HIGH"]

        # Local broker
        if broker_host in ["localhost", "127.0.0.1", "0.0.0.0"]:
            self._add_finding(findings, "INFO", "Local Broker Detected",
                              "Development/testing environment")

        latency = self._measure_latency(start_time)
        risk_score = min(risk_score, 100)

        return AnalysisResult(
            success=True,
            message="Connection analyzed successfully",
            risk_score=risk_score,
            latency=latency,
            security_findings=[{
                "severity": f.severity, "title": f.title, "description": f.description,
                "cwe": f.cwe, "owasp": f.owasp
            } for f in findings]
        )

    def analyze_publish(self, data: Dict[str, Any]) -> AnalysisResult:
        start_time = time.perf_counter()
        findings = []
        risk_score = 0

        topic = data.get("topic", "")
        payload = str(data.get("payload", ""))
        retain = data.get("retain", False)

        # Empty topic
        if not topic or not topic.strip():
            self._add_finding(findings, "HIGH", "Empty Topic",
                              "MQTT publish topic cannot be empty", cwe="CWE-284")
            risk_score += self.severity_weights["HIGH"]

        # Topic validation
        if topic.startswith("$SYS") or "$sys" in topic.lower():
            self._add_finding(findings, "CRITICAL", "System Topic Publish",
                              "Publishing to broker system topics", cwe="CWE-306")
            risk_score += self.severity_weights["CRITICAL"]

        if "#" in topic or "+" in topic:
            self._add_finding(findings, "CRITICAL", "Wildcard in Publish Topic",
                              "Wildcards not allowed when publishing", cwe="CWE-284")
            risk_score += self.severity_weights["CRITICAL"]

        # Payload analysis
        if payload:
            for pattern in self.injection_patterns:
                if re.search(pattern, payload, re.IGNORECASE):
                    self._add_finding(findings, "CRITICAL", "Potential Malicious Payload",
                                      "IoT attack patterns detected in payload", cwe="CWE-94")
                    risk_score += self.severity_weights["CRITICAL"]
                    break

            for pattern in self.sensitive_patterns:
                if re.search(pattern, payload, re.IGNORECASE):
                    self._add_finding(findings, "HIGH", "Sensitive Data Exposure",
                                      "Credentials or secrets in payload", cwe="CWE-312", owasp="I7")
                    risk_score += self.severity_weights["HIGH"]
                    break

            # Dangerous retained messages
            if retain:
                if re.search(r"(password|token|secret|apikey|auth|config)", payload, re.IGNORECASE) or \
                   any(d in topic.lower() for d in ["config", "password", "secret"]):
                    self._add_finding(findings, "HIGH", "Sensitive Retained Message",
                                      "Sensitive data stored in retained message", cwe="CWE-312", owasp="I7")
                    risk_score += self.severity_weights["HIGH"]

        # Payload size (tiered)
        payload_len = len(payload)
        if payload_len > 100000:
            self._add_finding(findings, "HIGH", "Extreme Payload Size",
                              "Very large payload (>100KB) - possible DoS or abuse")
            risk_score += self.severity_weights["HIGH"]
        elif payload_len > 10000:
            self._add_finding(findings, "MEDIUM", "Large Payload",
                              "Large payload may indicate abuse")
            risk_score += self.severity_weights["MEDIUM"]

        latency = self._measure_latency(start_time)
        risk_score = min(risk_score, 100)

        return AnalysisResult(
            success=True,
            message="Publish analyzed successfully",
            risk_score=risk_score,
            latency=latency,
            security_findings=[{
                "severity": f.severity, "title": f.title, "description": f.description,
                "cwe": f.cwe, "owasp": f.owasp
            } for f in findings]
        )

    def analyze_subscribe(self, data: Dict[str, Any]) -> AnalysisResult:
        start_time = time.perf_counter()
        findings = []
        risk_score = 0
        seen = set()

        topics = data.get("topics", [])

        if not topics:
            self._add_finding(findings, "LOW", "No Topics Specified",
                              "Subscribe request contains no topics")

        for topic in topics:
            if topic in seen: 
                continue
            seen.add(topic)

            if topic == "#" or topic.endswith("#"):
                self._add_finding(findings, "HIGH", "Overly Broad Subscription",
                                  "Wildcard # subscribes to all topics", cwe="CWE-732")
                risk_score += self.severity_weights["HIGH"]
            elif "#" in topic:
                self._add_finding(findings, "MEDIUM", "Multi-level Wildcard",
                                  "Using # wildcard increases attack surface")
                risk_score += self.severity_weights["MEDIUM"]

            if any(d.lower() in topic.lower() for d in self.dangerous_topics):
                self._add_finding(findings, "MEDIUM", "Sensitive Topic Subscription",
                                  f"Subscribing to sensitive topic: {topic}")

        latency = self._measure_latency(start_time)
        risk_score = min(risk_score, 100)

        return AnalysisResult(
            success=True,
            message="Subscription analyzed successfully",
            risk_score=risk_score,
            latency=latency,
            security_findings=[{
                "severity": f.severity, "title": f.title, "description": f.description,
                "cwe": f.cwe, "owasp": f.owasp
            } for f in findings]
        )

    def analyze_disconnect(self, data: Dict[str, Any]) -> AnalysisResult:
        start_time = time.perf_counter()
        return AnalysisResult(
            success=True,
            message="Disconnection analyzed successfully",
            risk_score=0,
            latency=self._measure_latency(start_time),
            security_findings=[]
        )


# ============ Main Entry Point ============
def analyze_request(endpoint: str, data: Dict[str, Any]) -> Dict[str, Any]:
    analyzer = MQTTSecurityAnalyzer()

    if endpoint == "connect":
        result = analyzer.analyze_connect(data)
    elif endpoint == "publish":
        result = analyzer.analyze_publish(data)
    elif endpoint == "subscribe":
        result = analyzer.analyze_subscribe(data)
    elif endpoint == "disconnect":
        result = analyzer.analyze_disconnect(data)
    else:
        return {"success": False, "message": f"Unknown endpoint: {endpoint}", "riskScore": 0, "securityFindings": []}

    return {
        "success": result.success,
        "message": result.message,
        "latency": result.latency,
        "riskScore": result.risk_score,
        "securityFindings": result.security_findings
    }
