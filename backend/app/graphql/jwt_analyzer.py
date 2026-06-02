import base64
import json

from datetime import datetime
from typing import Dict, Any


class JWTAnalyzer:

    @staticmethod
    def decode_base64(data: str):

        """
        Safely decode base64 JWT section
        """

        padding = "=" * (-len(data) % 4)

        return base64.urlsafe_b64decode(
            data + padding
        ).decode("utf-8")

    @staticmethod
    def analyze(token: str) -> Dict[str, Any]:

        result = {

            # =====================================
            # BASIC INFO
            # =====================================

            "valid_structure": False,

            "algorithm": None,

            "token_type": None,

            "issuer": None,

            "audience": None,

            "subject": None,

            # =====================================
            # TIME INFO
            # =====================================

            "issued_at": None,

            "expires_at": None,

            "expired": False,

            # =====================================
            # PAYLOADS
            # =====================================

            "header": {},

            "payload": {},

            # =====================================
            # SECURITY FINDINGS
            # =====================================

            "findings": []
        }

        try:

            # =====================================
            # REMOVE BEARER PREFIX
            # =====================================

            if token.startswith("Bearer "):

                token = token.split(" ")[1]

            # =====================================
            # SPLIT JWT
            # =====================================

            parts = token.split(".")

            if len(parts) != 3:

                result["findings"].append(
                    "Invalid JWT structure"
                )

                return result

            result["valid_structure"] = True

            # =====================================
            # DECODE HEADER
            # =====================================

            header = json.loads(
                JWTAnalyzer.decode_base64(
                    parts[0]
                )
            )

            # =====================================
            # DECODE PAYLOAD
            # =====================================

            payload = json.loads(
                JWTAnalyzer.decode_base64(
                    parts[1]
                )
            )

            result["header"] = header

            result["payload"] = payload

            # =====================================
            # ALGORITHM
            # =====================================

            alg = header.get("alg")

            result["algorithm"] = alg

            if alg:

                if alg.lower() == "none":

                    result["findings"].append(
                        "JWT uses NONE algorithm"
                    )

                elif alg.lower() in [
                    "hs1",
                    "md5"
                ]:

                    result["findings"].append(
                        f"Weak JWT algorithm detected: {alg}"
                    )

            else:

                result["findings"].append(
                    "JWT algorithm missing"
                )

            # =====================================
            # TOKEN TYPE
            # =====================================

            result["token_type"] = header.get("typ")

            # =====================================
            # ISSUER / AUDIENCE / SUBJECT
            # =====================================

            result["issuer"] = payload.get("iss")

            result["audience"] = payload.get("aud")

            result["subject"] = payload.get("sub")

            # =====================================
            # EXPIRATION
            # =====================================

            exp = payload.get("exp")

            if exp:

                result["expires_at"] = datetime.utcfromtimestamp(
                    exp
                ).isoformat()

                now = datetime.utcnow().timestamp()

                if now > exp:

                    result["expired"] = True

                    result["findings"].append(
                        "JWT token expired"
                    )

            else:

                result["findings"].append(
                    "JWT expiration claim missing"
                )

            # =====================================
            # ISSUED AT
            # =====================================

            iat = payload.get("iat")

            if iat:

                result["issued_at"] = datetime.utcfromtimestamp(
                    iat
                ).isoformat()

            # =====================================
            # LONG EXPIRATION CHECK
            # =====================================

            if exp and iat:

                token_lifetime = exp - iat

                if token_lifetime > 60 * 60 * 24 * 30:

                    result["findings"].append(
                        "JWT expiration time too long"
                    )

            # =====================================
            # MISSING ISSUER
            # =====================================

            if not result["issuer"]:

                result["findings"].append(
                    "JWT issuer claim missing"
                )

            # =====================================
            # MISSING AUDIENCE
            # =====================================

            if not result["audience"]:

                result["findings"].append(
                    "JWT audience claim missing"
                )

            return result

        except Exception as e:

            result["findings"].append(
                f"JWT decode error: {str(e)}"
            )

            return result
