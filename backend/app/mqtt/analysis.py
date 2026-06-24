import re
import time
import json
import base64
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

        self.injection_patterns = [
            r"\$\{[^}]+\}", r"{{[^}]+}}", r"<script", r"javascript:", r"on\w+\s*=",
            r"eval\s*\(", r"exec\s*\(",
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

        self.iot_sensitive_topics = [
            "firmware", "update", "ota", "reboot", "shutdown", "factory_reset",
            "admin", "management", "control", "device_control"
        ]

        # ── FIXED PII patterns ──────────────────────────────────────────────
        # Removed: generic 10-digit number (matched sensor values),
        #          15-digit number (too broad),
        #          bare decimal IP regex (matched float telemetry like 24.5/48.2),
        #          [A-Z0-9-]{10,} (matched device IDs like sensor_x42, topic segments)
        self.pii_patterns = [
            # Real email addresses
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',

            # Phone numbers: require separators (e.g. +1 800-555-1234 or 800 555 1234)
            r'(?<!\d\.)\b(?:\+\d{1,2}[\s-])?\d{3}[\s-]\d{3}[\s-]\d{4}\b',

            # Credit card: 16 digits grouped (NNNN-NNNN-NNNN-NNNN) or continuous
            r'\b(?:\d{4}[\s-]){3}\d{4}\b',
            r'\b\d{16}\b',

            # SSN: NNN-NN-NNNN format only
            r'\b\d{3}-\d{2}-\d{4}\b',

            # Strict IPv4: each octet must be 0-255 (won't match floats like 24.5)
            r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
        ]
        # ────────────────────────────────────────────────────────────────────

        self.jwt_patterns = [r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+']
        self.base64_patterns = [r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?']

        self.command_injection_patterns = [
            r'reboot', r'shutdown', r'wipe', r'erase', r'factory_reset',
            r'ota_update', r'firmware_update'
        ]

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

    # ==================== Helper Scanners ====================
    def _scan_json(self, payload: str, findings: List, risk_score: int) -> int:
        try:
            data = json.loads(payload)
            return self._scan_dict(data, findings, risk_score)
        except (json.JSONDecodeError, TypeError):
            return risk_score

    def _scan_dict(self, data: Any, findings: List, risk_score: int) -> int:
        if isinstance(data, dict):
            for key, value in data.items():
                key_lower = key.lower()
                if any(s in key_lower for s in ['password', 'secret', 'token', 'key', 'auth', 'credential']):
                    self._add_finding(findings, "HIGH", "Nested Credential Exposure",
                                      f"Sensitive key '{key}' in JSON payload", cwe="CWE-312", owasp="I7")
                    risk_score += self.severity_weights["HIGH"]
                if isinstance(value, (dict, list)):
                    risk_score = self._scan_dict(value, findings, risk_score)
                elif isinstance(value, str):
                    risk_score = self._scan_string(value, findings, risk_score)
        elif isinstance(data, list):
            for item in data:
                risk_score = self._scan_dict(item, findings, risk_score)
        return risk_score

    def _scan_string(self, s: str, findings: List, risk_score: int) -> int:
        for pattern in self.pii_patterns:
            if re.search(pattern, s):
                self._add_finding(findings, "HIGH", "PII Exposure",
                                  "Personally identifiable information detected", cwe="CWE-359", owasp="I6")
                risk_score += self.severity_weights["HIGH"]
                break

        for pattern in self.jwt_patterns:
            if re.search(pattern, s):
                self._add_finding(findings, "HIGH", "JWT Exposure",
                                  "JSON Web Token detected in payload", cwe="CWE-312", owasp="I7")
                risk_score += self.severity_weights["HIGH"]
                break

        for pattern in self.base64_patterns:
            matches = re.findall(pattern, s)
            for match in matches:
                if len(match) > 20:
                    try:
                        decoded = base64.b64decode(match + '==').decode('utf-8', errors='ignore')
                        if any(kw in decoded.lower() for kw in ['password', 'secret', 'admin', 'token']):
                            self._add_finding(findings, "MEDIUM", "Encoded Sensitive Content",
                                              "Base64 encoded sensitive data", cwe="CWE-312")
                            risk_score += self.severity_weights["MEDIUM"]
                    except Exception:
                        pass
        return risk_score

    def _scan_topic(self, topic: str, findings: List, risk_score: int, is_publish: bool = False) -> int:
        topic_lower = topic.lower()
        if any(s in topic_lower for s in self.iot_sensitive_topics):
            severity = "CRITICAL" if is_publish else "HIGH"
            self._add_finding(findings, severity, "Sensitive Topic",
                              f"Accessing sensitive IoT topic: {topic}", cwe="CWE-200")
            risk_score += self.severity_weights[severity]

        if "../" in topic or "../../" in topic:
            self._add_finding(findings, "HIGH", "Topic Traversal Attempt",
                              "Potential directory traversal in topic", cwe="CWE-22")
            risk_score += self.severity_weights["HIGH"]
        return risk_score

    def _scan_device_commands(self, payload: str, findings: List, risk_score: int) -> int:
        payload_lower = payload.lower()
        for cmd in self.command_injection_patterns:
            if cmd in payload_lower:
                self._add_finding(findings, "CRITICAL", "Dangerous Device Command",
                                  f"Potential dangerous command '{cmd}' in payload", cwe="CWE-94")
                risk_score += self.severity_weights["CRITICAL"]
                break
        return risk_score

    def _scan_device_metadata(self, payload: str, findings: List, risk_score: int) -> int:
        payload_lower = payload.lower()
        metadata_keywords = ["firmware", "version", "hardware", "chipset", "esp32", "stm32", "raspberrypi"]
        if any(kw in payload_lower for kw in metadata_keywords):
            self._add_finding(findings, "MEDIUM", "Device Fingerprinting",
                              "Device metadata exposure detected", cwe="CWE-200", owasp="I6")
            risk_score += self.severity_weights["MEDIUM"]
        return risk_score

    def _check_password_strength(self, password: str, findings: List, risk_score: int) -> int:
        if len(password) < 8:
            self._add_finding(findings, "MEDIUM", "Short Password", "Password is too short", cwe="CWE-521")
            risk_score += self.severity_weights["MEDIUM"]

        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)

        if not (has_upper and has_lower and has_digit and has_special):
            self._add_finding(findings, "HIGH", "Weak Credential Policy",
                              "Password lacks complexity (upper, lower, digit, special)", cwe="CWE-521")
            risk_score += self.severity_weights["HIGH"]
        return risk_score

    def _check_username(self, username: str, findings: List, risk_score: int) -> int:
        weak_usernames = ["admin", "root", "guest", "anonymous", "demo", "test"]
        if username.lower() in weak_usernames:
            self._add_finding(findings, "HIGH", "Predictable Username",
                              f"Weak username: {username}", cwe="CWE-798")
            risk_score += self.severity_weights["HIGH"]
        return risk_score

    # ==================== Analysis Methods ====================
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

        if not broker_host or not broker_host.strip():
            self._add_finding(findings, "HIGH", "Missing Broker Host",
                              "Broker host is empty or not specified", cwe="CWE-284")
            risk_score += self.severity_weights["HIGH"]
        else:
            if re.match(r'^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)', broker_host):
                self._add_finding(findings, "INFO", "Private Network Broker",
                                  "Broker on private/internal network", cwe="CWE-284")
            if broker_host in ["localhost", "127.0.0.1", "0.0.0.0"]:
                self._add_finding(findings, "INFO", "Local Broker Detected",
                                  "Development/testing environment")

        if not tls_enabled:
            self._add_finding(findings, "HIGH", "Unencrypted Connection",
                              "Using unencrypted MQTT without TLS", cwe="CWE-319", owasp="I7")
            risk_score += self.severity_weights["HIGH"]
        elif tls_enabled and tls_insecure:
            self._add_finding(findings, "HIGH", "TLS Certificate Validation Disabled",
                              "Server certificate verification is disabled", cwe="CWE-295", owasp="I7")
            risk_score += self.severity_weights["HIGH"]

        if broker_port == 1883:
            if tls_enabled:
                self._add_finding(findings, "MEDIUM", "TLS on Standard MQTT Port",
                                  "TLS enabled but using default non-TLS port 1883")
            else:
                self._add_finding(findings, "HIGH", "Plain MQTT Port",
                                  "Using standard unencrypted MQTT port 1883")

        if not username and not password:
            self._add_finding(findings, "CRITICAL", "No Authentication",
                              "Anonymous access enabled", cwe="CWE-306", owasp="I3")
            risk_score += self.severity_weights["CRITICAL"]
        elif not username or not password:
            self._add_finding(findings, "HIGH", "Incomplete Authentication",
                              "Missing username or password", cwe="CWE-287")
            risk_score += self.severity_weights["HIGH"]
        else:
            risk_score = self._check_username(username, findings, risk_score)
            if password.lower() in self.weak_passwords:
                self._add_finding(findings, "HIGH", "Weak Password Detected",
                                  "Commonly used password", cwe="CWE-521")
                risk_score += self.severity_weights["HIGH"]
            else:
                risk_score = self._check_password_strength(password, findings, risk_score)

        if not client_id:
            self._add_finding(findings, "MEDIUM", "No Client ID Provided",
                              "Broker will auto-generate ID", cwe="CWE-284")
            risk_score += self.severity_weights["MEDIUM"]
        else:
            predictable = ["client", "mqtt", "test", "device", "sensor", "esp32", "node"]
            if any(p in client_id.lower() for p in predictable) or client_id.endswith("123") or re.match(r'device\d+', client_id.lower()):
                self._add_finding(findings, "MEDIUM", "Predictable Client ID",
                                  "Using common or weak client ID - enumeration risk", cwe="CWE-798")
                risk_score += self.severity_weights["MEDIUM"]
            elif len(client_id) < 6:
                self._add_finding(findings, "MEDIUM", "Short Client ID",
                                  "Client ID is too short", cwe="CWE-284")
                risk_score += self.severity_weights["MEDIUM"]

        if qos == 0:
            self._add_finding(findings, "LOW", "QoS 0 Used",
                              "No delivery guarantee - messages may be lost")
        elif qos == 2:
            self._add_finding(findings, "INFO", "QoS 2 Used",
                              "Highest delivery guarantee enabled")

        seen = set()
        for t in subscribe_topics:
            if t in seen:
                continue
            seen.add(t)
            risk_score = self._scan_topic(t, findings, risk_score, is_publish=False)

            if t == "#" or t.endswith("#"):
                self._add_finding(findings, "HIGH", "Overly Broad Subscription",
                                  "Wildcard # subscribes to all topics", cwe="CWE-732")
                risk_score += self.severity_weights["HIGH"]
            if t.startswith("$SYS") or "$sys" in t.lower():
                self._add_finding(findings, "HIGH", "System Topic Subscription",
                                  "Accessing internal broker topics", cwe="CWE-200")
                risk_score += self.severity_weights["HIGH"]

        latency = self._measure_latency(start_time)
        risk_score = min(risk_score, 100)

        return AnalysisResult(
            success=True,
            message="Connection analyzed successfully",
            risk_score=risk_score,
            latency=latency,
            security_findings=[{
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "cwe": f.cwe,
                "owasp": f.owasp
            } for f in findings]
        )

    def analyze_publish(self, data: Dict[str, Any]) -> AnalysisResult:
        start_time = time.perf_counter()
        findings = []
        risk_score = 0

        topic = data.get("topic", "")
        payload = str(data.get("payload", ""))
        retain = data.get("retain", False)

        if not topic or not topic.strip():
            self._add_finding(findings, "HIGH", "Empty Topic",
                              "MQTT publish topic cannot be empty", cwe="CWE-284")
            risk_score += self.severity_weights["HIGH"]
        else:
            risk_score = self._scan_topic(topic, findings, risk_score, is_publish=True)

            if topic.startswith("$SYS") or "$sys" in topic.lower():
                self._add_finding(findings, "CRITICAL", "System Topic Publish",
                                  "Publishing to broker system topics", cwe="CWE-306")
                risk_score += self.severity_weights["CRITICAL"]

            if "#" in topic or "+" in topic:
                self._add_finding(findings, "CRITICAL", "Wildcard in Publish Topic",
                                  "Wildcards not allowed when publishing", cwe="CWE-284")
                risk_score += self.severity_weights["CRITICAL"]

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

            if '{' in payload:
                risk_score = self._scan_json(payload, findings, risk_score)

            risk_score = self._scan_string(payload, findings, risk_score)
            risk_score = self._scan_device_commands(payload, findings, risk_score)
            risk_score = self._scan_device_metadata(payload, findings, risk_score)

            if re.search(r'"debug"\s*:\s*true', payload, re.IGNORECASE) or \
               re.search(r'"maintenance"\s*:\s*true', payload, re.IGNORECASE):
                self._add_finding(findings, "HIGH", "Debug Interface Exposed",
                                  "Debug or maintenance mode enabled", cwe="CWE-200")
                risk_score += self.severity_weights["HIGH"]

            if len(payload) > 100000:
                self._add_finding(findings, "HIGH", "Extreme Payload Size",
                                  "Very large payload (>100KB) - possible DoS or abuse")
                risk_score += self.severity_weights["HIGH"]
            elif len(payload) > 10000 or len(re.findall(r'A{20,}', payload)) > 0 or \
                 ('{' in payload and payload.count('{') > 50):
                self._add_finding(findings, "MEDIUM", "Potential DoS Payload",
                                  "Large, repetitive, or deeply nested payload detected")
                risk_score += self.severity_weights["MEDIUM"]

            if retain:
                sensitive_retained = ["password", "secret", "token", "firmware", "factory_reset", "reboot", "shutdown", "ota"]
                if any(s in payload.lower() for s in sensitive_retained) or \
                   any(d in topic.lower() for d in ["config", "password", "secret"]):
                    self._add_finding(findings, "CRITICAL", "Dangerous Retained Command/Message",
                                      "Sensitive or dangerous data in retained message", cwe="CWE-312", owasp="I7")
                    risk_score += self.severity_weights["CRITICAL"]

        latency = self._measure_latency(start_time)
        risk_score = min(risk_score, 100)

        return AnalysisResult(
            success=True,
            message="Publish analyzed successfully",
            risk_score=risk_score,
            latency=latency,
            security_findings=[{
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "cwe": f.cwe,
                "owasp": f.owasp
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

            risk_score = self._scan_topic(topic, findings, risk_score, is_publish=False)

            if topic == "#" or topic.endswith("#") or "+/+" in topic or topic.count('+') > 1:
                self._add_finding(findings, "HIGH", "Overly Broad Subscription",
                                  "Broad wildcard subscription increases attack surface", cwe="CWE-732")
                risk_score += self.severity_weights["HIGH"]
            elif "#" in topic or "+" in topic:
                self._add_finding(findings, "MEDIUM", "Multi-level Wildcard",
                                  "Using wildcards increases attack surface")
                risk_score += self.severity_weights["MEDIUM"]

            recon_topics = ["metrics", "health", "statistics", "broker", "monitoring"]
            if any(rt in topic.lower() for rt in recon_topics):
                self._add_finding(findings, "MEDIUM", "Broker Reconnaissance",
                                  "Subscribing to broker intelligence topics", cwe="CWE-200")

        latency = self._measure_latency(start_time)
        risk_score = min(risk_score, 100)

        return AnalysisResult(
            success=True,
            message="Subscription analyzed successfully",
            risk_score=risk_score,
            latency=latency,
            security_findings=[{
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "cwe": f.cwe,
                "owasp": f.owasp
            } for f in findings]
        )

    def analyze_disconnect(self, data: Dict[str, Any]) -> AnalysisResult:
        start_time = time.perf_counter()
        findings = []
        risk_score = 0

        reason = data.get("reason", "")
        if reason and any(r in reason.lower() for r in ["crash", "timeout", "error", "disconnect"]):
            self._add_finding(findings, "MEDIUM", "Abnormal Disconnect",
                              f"Disconnect reason: {reason}", cwe="CWE-400")

        latency = self._measure_latency(start_time)

        return AnalysisResult(
            success=True,
            message="Disconnection analyzed successfully",
            risk_score=risk_score,
            latency=latency,
            security_findings=[{
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "cwe": f.cwe,
                "owasp": f.owasp
            } for f in findings]
        )


# ============ Main Entry Point ============
def sanitize_finding(f: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "severity": str(f.get("severity", "LOW")),
        "title": str(f.get("title", "Unknown Issue")),
        "description": str(f.get("description", "No description provided.")),
        "cwe": str(f.get("cwe")) if f.get("cwe") is not None else None,
        "owasp": str(f.get("owasp")) if f.get("owasp") is not None else None,
    }


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
        return {
            "success": False,
            "message": f"Unknown endpoint: {endpoint}",
            "riskScore": 0,
            "securityFindings": []
        }

    security_findings = [sanitize_finding(f) for f in result.security_findings]

    return {
        "success": result.success,
        "message": result.message,
        "latency": str(result.latency or "--"),
        "riskScore": result.risk_score,
        "securityFindings": security_findings
    }
