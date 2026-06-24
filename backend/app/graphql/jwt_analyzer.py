import base64
import json
import re
from datetime import datetime
from typing import Dict, Any


class JWTAnalyzer:

    WEAK_ALGORITHMS = ["none", "hs1", "md5", "sha1"]
    
    SECRET_KEYS = [
        "password", "secret", "apikey", "api_key",
        "access_token", "refresh_token", "private_key"
    ]

    REQUIRED_CLAIMS = ["exp", "iat", "iss", "aud", "sub"]

    HIGH_RISK_CLAIMS = ["role", "roles", "scope", "permissions", "groups", "admin", "isAdmin"]

    SUSPICIOUS_KID_PATTERNS = [
        r"\.\./", r"\\", r"'", r'"', r";", r"\.\.", r"/etc/", r"passwd", r"shadow"
    ]

    @staticmethod
    def decode_base64(data: str):
        """Safely decode base64 JWT section"""
        padding = "=" * (-len(data) % 4)
        return base64.urlsafe_b64decode(data + padding).decode("utf-8")

    @staticmethod
    def analyze(token: str) -> Dict[str, Any]:
        result = {
            "valid_structure": False,
            "algorithm": None,
            "token_type": None,
            "issuer": None,
            "audience": None,
            "subject": None,
            "jwt_id": None,
            "kid": None,
            "jku": None,
            "x5u": None,
            "cty": None,

            "issued_at": None,
            "expires_at": None,
            "not_before": None,
            "expired": False,

            "header": {},
            "payload": {},

            "findings": [],
            "security_score": 100,
            "signature_verified": False,
        }

        try:
            # Remove Bearer prefix
            if token.startswith("Bearer "):
                token = token.split(" ")[1]

            # Split JWT
            parts = token.split(".")

            if len(parts) != 3:
                result["findings"].append("Invalid JWT structure")
                return result

            # Signature check
            if not parts[2] or parts[2].strip() == "":
                result["findings"].append("JWT signature missing (unsigned token)")

            result["valid_structure"] = True
            result["signature_verified"] = False

            # Decode Header & Payload
            header = json.loads(JWTAnalyzer.decode_base64(parts[0]))
            payload = json.loads(JWTAnalyzer.decode_base64(parts[1]))

            result["header"] = header
            result["payload"] = payload

            # === HEADER ANALYSIS ===
            alg = header.get("alg")
            result["algorithm"] = alg
            result["kid"] = header.get("kid")
            result["jku"] = header.get("jku")
            result["x5u"] = header.get("x5u")
            result["cty"] = header.get("cty")
            result["token_type"] = header.get("typ")

            if alg:
                if alg.lower() in JWTAnalyzer.WEAK_ALGORITHMS:
                    result["findings"].append(f"Weak JWT algorithm detected: {alg}")
            else:
                result["findings"].append("JWT algorithm missing")

            # kid Analysis
            if result["kid"]:
                kid_lower = str(result["kid"]).lower()
                for pattern in JWTAnalyzer.SUSPICIOUS_KID_PATTERNS:
                    if re.search(pattern, kid_lower):
                        result["findings"].append("Suspicious 'kid' header - possible path traversal or injection")
                        break

            # jku & x5u Analysis
            if result["jku"]:
                result["findings"].append(f"External JWK Set URL (jku) detected: {result['jku']}")
            if result["x5u"]:
                result["findings"].append(f"External certificate URL (x5u) detected: {result['x5u']}")

            # Nested JWT
            if result["cty"] and str(result["cty"]).upper() == "JWT":
                result["findings"].append("Nested JWT detected (cty: JWT)")

            # === PAYLOAD ANALYSIS ===
            now = datetime.utcnow().timestamp()

            result["issuer"] = payload.get("iss")
            result["audience"] = payload.get("aud")
            result["subject"] = payload.get("sub")
            result["jwt_id"] = payload.get("jti")
            result["nonce"] = payload.get("nonce")

            # Time Claims with Proper Validation
            time_claims = [
                ("exp", "expires_at"),
                ("iat", "issued_at"),
                ("nbf", "not_before")
            ]

            for claim_name, result_key in time_claims:
                val = payload.get(claim_name)
                if val is not None:
                    if not isinstance(val, (int, float)):
                        result["findings"].append(f"Invalid {claim_name} claim type (should be numeric timestamp)")
                    else:
                        try:
                            dt = datetime.utcfromtimestamp(val)
                            result[result_key] = dt.isoformat()

                            if claim_name == "exp":
                                if now > val:
                                    result["expired"] = True
                                    result["findings"].append("JWT token has expired")
                            elif claim_name == "iat":
                                if val > now:
                                    result["findings"].append("JWT issued in the future")
                            elif claim_name == "nbf":
                                if now < val:
                                    result["findings"].append("JWT token is not yet valid (nbf)")
                        except Exception:
                            result["findings"].append(f"Invalid timestamp value for {claim_name}")

            # Lifetime & Age Checks
            exp = payload.get("exp")
            iat = payload.get("iat")
            if exp and iat and isinstance(exp, (int, float)) and isinstance(iat, (int, float)):
                lifetime = exp - iat
                if lifetime > 60 * 60 * 24 * 7:   # 7 days
                    result["findings"].append(f"JWT lifetime too long ({lifetime // 86400} days)")

                age = now - iat
                if age > 60 * 60 * 24 * 365:
                    result["findings"].append("JWT is extremely old (> 1 year)")

            # Required Claims
            for claim in JWTAnalyzer.REQUIRED_CLAIMS:
                if claim not in payload:
                    result["findings"].append(f"Missing recommended JWT claim: {claim}")

            # Missing Subject, JTI, Audience
            if not result["subject"]:
                result["findings"].append("JWT subject claim (sub) missing")
            if not result.get("jwt_id"):
                result["findings"].append("JWT ID (jti) missing - replay attacks more likely")
            if not result.get("audience"):
                result["findings"].append("JWT audience claim (aud) missing")
            if result.get("nonce") is None:
                result["findings"].append("nonce claim missing (recommended for OIDC replay protection)")

            # Sensitive Data in Payload
            for key in JWTAnalyzer.SECRET_KEYS:
                if key in payload:
                    result["findings"].append(f"Sensitive data present in JWT payload: {key}")

            # High Risk Privilege Claims
            for claim in JWTAnalyzer.HIGH_RISK_CLAIMS:
                if claim in payload:
                    result["findings"].append(f"High-risk privilege claim detected: {claim}")

            # Oversized JWT
            if len(token) > 4096:
                result["findings"].append("JWT size unusually large (> 4KB)")

            # === FINAL SECURITY SCORE ===
            finding_count = len(result["findings"])
            result["security_score"] = max(0, 100 - (finding_count * 7))

            # Signature Verification Note
            if not result["signature_verified"]:
                result["findings"].append("Signature verification was NOT performed (no secret/public key provided)")

            return result

        except Exception as e:
            result["findings"].append(f"JWT decode error: {str(e)}")
            result["security_score"] = 0
            return result
