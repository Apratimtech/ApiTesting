import httpx
import time
import uuid
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("api_executor")


# ---------------------------------------------------------
# 🔹 Utility: Generate unique Request ID
# ---------------------------------------------------------
def generate_request_id() -> str:
    return str(uuid.uuid4())


# ---------------------------------------------------------
# 🔹 Utility: Sanitize headers/body for security
# ---------------------------------------------------------
class Sanitizer:
    SENSITIVE_KEYS = ["password", "token", "secret", "authorization"]

    @staticmethod
    def sanitize_dict(data: Dict[str, Any]) -> Dict[str, Any]:
        if not data:
            return {}
        safe = {}
        for k, v in data.items():
            if k.lower() in Sanitizer.SENSITIVE_KEYS:
                safe[k] = "***hidden***"
            else:
                safe[k] = v
        return safe


# ---------------------------------------------------------
# 🔹 Utility: Security Validation
# ---------------------------------------------------------
class SecurityValidator:
    @staticmethod
    def validate_url(url: str):
        if not (url.startswith("http://") or url.startswith("https://")):
            raise ValueError("Invalid URL: Must start with http:// or https://")

    @staticmethod
    def validate_method(method: str):
        allowed = {"GET", "POST", "PUT", "PATCH", "DELETE"}
        if method.upper() not in allowed:
            raise ValueError(f"Unsupported HTTP method: {method}")


# ---------------------------------------------------------
# 🔹 Utility: Metrics Collector
# ---------------------------------------------------------
class MetricsCollector:
    def __init__(self):
        self.metrics = {}

    def record(self, request_id: str, elapsed_ms: int):
        self.metrics[request_id] = {
            "response_time_ms": elapsed_ms,
        }

    def get(self, request_id: str):
        return self.metrics.get(request_id, {})


# ---------------------------------------------------------
# 🔹 Utility: Response Formatter
# ---------------------------------------------------------
class ResponseFormatter:
    @staticmethod
    def format(response: httpx.Response, elapsed_ms: int, request_id: str):
        return {
            "request_id": request_id,
            "status": response.status_code,
            "headers": dict(response.headers),
            "data": ResponseFormatter._parse_body(response),
            "time": f"{elapsed_ms}ms",
        }

    @staticmethod
    def _parse_body(response):
        try:
            return response.json()
        except Exception:
            return response.text


# ---------------------------------------------------------
# 🔹 Retry Logic
# ---------------------------------------------------------
async def retry_request(client, method, url, headers, body, retries=2, delay=0.5):
    for attempt in range(retries + 1):
        try:
            return await client.request(
                method=method,
                url=url,
                headers=headers,
                json=body if isinstance(body, dict) else None,
            )
        except httpx.HTTPError as err:
            logger.error(f"Retry {attempt}: {str(err)}")

            if attempt == retries:
                raise err

            time.sleep(delay)


# ---------------------------------------------------------
# 🔹 Main Executor — combines all features
# ---------------------------------------------------------
class APIExecutor:
    def __init__(self):
        self.metrics = MetricsCollector()

    async def execute(
        self,
        method: str,
        url: str,
        headers: Optional[Dict] = None,
        body: Optional[Any] = None,
        timeout: int = 20,
    ):
        # 1️⃣ Generate request ID
        request_id = generate_request_id()

        # 2️⃣ Validate
        SecurityValidator.validate_method(method)
        SecurityValidator.validate_url(url)

        # 3️⃣ Sanitize logs
        safe_headers = Sanitizer.sanitize_dict(headers or {})
        safe_body = Sanitizer.sanitize_dict(body or {}) if isinstance(body, dict) else body

        logger.info(f"[{request_id}] Executing {method} {url}")
        logger.debug(f"[{request_id}] Headers: {safe_headers}")
        logger.debug(f"[{request_id}] Body: {safe_body}")

        # 4️⃣ Execute
        start = time.time()

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await retry_request(
                    client, method, url, headers or {}, body, retries=2
                )

            elapsed_ms = round((time.time() - start) * 1000)

            # 5️⃣ Record metrics
            self.metrics.record(request_id, elapsed_ms)

            # 6️⃣ Format and return response
            return ResponseFormatter.format(response, elapsed_ms, request_id)

        except Exception as e:
            logger.error(f"[{request_id}] Error: {str(e)}")
            return {
                "request_id": request_id,
                "error": str(e),
                "time": f"{round((time.time() - start) * 1000)}ms",
            }


# ---------------------------------------------------------
# ⭐ Legacy Support (your old function upgraded)
# ---------------------------------------------------------
async def execute_request(method, url, headers=None, body=None):
    executor = APIExecutor()
    return await executor.execute(method, url, headers, body)
