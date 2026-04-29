import httpx
import logging
from typing import Dict, Any

logger = logging.getLogger("request_engine")


class RequestEngine:

    async def send_request(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        params: Dict[str, str],
        body: Any,
        auth,
        timeout: int,
    ):
        headers = headers or {}
        params = params or {}

        # 🔐 AUTH HANDLING
        if auth:
            if auth.type == "bearer" and auth.token:
                headers["Authorization"] = f"Bearer {auth.token}"

            elif auth.type == "api_key" and auth.key:
                headers[auth.key] = auth.value

            elif auth.type == "basic" and auth.username:
                import base64
                token = base64.b64encode(
                    f"{auth.username}:{auth.password}".encode()
                ).decode()
                headers["Authorization"] = f"Basic {token}"

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    params=params,
                    json=body if isinstance(body, dict) else None,
                    content=body if isinstance(body, str) else None,
                )

            logger.info(f"{method} {url} -> {response.status_code}")

            return {
                "status": response.status_code,
                "headers": dict(response.headers),
                "body": self._parse_response(response),
            }

        except httpx.TimeoutException:
            logger.error("Request timeout")
            return {"error": "Request timed out"}

        except Exception as e:
            logger.error(str(e))
            return {"error": str(e)}

    def _parse_response(self, response):
        try:
            return response.json()
        except:
            return response.text
