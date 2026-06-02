import httpx
import time
import json
from typing import Dict, Any, Optional


class GraphQLClient:

    DEFAULT_TIMEOUT = 30

    MAX_RESPONSE_SIZE = 5 * 1024 * 1024

    BLOCKED_HOSTS = [
    ]

    @staticmethod
    def build_headers(
        headers: Dict[str, str],
        auth_type: Optional[str] = None,
        auth_value: Optional[str] = None
    ) -> Dict[str, str]:

        final_headers = headers.copy()

        final_headers.setdefault(
            "Content-Type",
            "application/json"
        )

        final_headers.setdefault(
            "User-Agent",
            "TrustEdge-GraphQL-Scanner/1.0"
        )

        if auth_type and auth_value:

            if auth_type == "Bearer Token":

                final_headers["Authorization"] = (
                    f"Bearer {auth_value}"
                )

            elif auth_type == "Basic Auth":

                final_headers["Authorization"] = (
                    f"Basic {auth_value}"
                )

            elif auth_type == "API Key":

                final_headers["X-API-Key"] = auth_value

        return final_headers

    # =====================================================
    # SSRF PROTECTION
    # =====================================================

    @staticmethod
    def validate_endpoint(endpoint: str):

        for host in GraphQLClient.BLOCKED_HOSTS:

            if host in endpoint:

                raise Exception(
                    "Blocked internal/private endpoint detected."
                )

    # =====================================================
    # MAIN EXECUTOR
    # =====================================================

    @staticmethod
    async def execute(
        endpoint: str,
        query: str,
        variables: Dict[str, Any],
        headers: Dict[str, str],
        auth_type: Optional[str] = None,
        auth_value: Optional[str] = None
    ) -> Dict[str, Any]:

        GraphQLClient.validate_endpoint(endpoint)

        final_headers = GraphQLClient.build_headers(
            headers=headers,
            auth_type=auth_type,
            auth_value=auth_value
        )

        payload = {
            "query": query,
            "variables": variables
        }

        start = time.time()

        try:

            async with httpx.AsyncClient(
                timeout=httpx.Timeout(
                    GraphQLClient.DEFAULT_TIMEOUT
                ),
                follow_redirects=False,
                verify=True
            ) as client:

                response = await client.post(
                    endpoint,
                    json=payload,
                    headers=final_headers
                )

            end = time.time()

            response_time = int(
                (end - start) * 1000
            )

            content_length = len(response.content)

            # =============================================
            # LARGE RESPONSE PROTECTION
            # =============================================

            if content_length > GraphQLClient.MAX_RESPONSE_SIZE:

                raise Exception(
                    "Response exceeded maximum allowed size."
                )

            # =============================================
            # SAFE JSON PARSING
            # =============================================

            try:

                response_json = response.json()

            except json.JSONDecodeError:

                response_json = {
                    "raw_response": response.text
                }

            return {
                "success": True,

                "status_code": response.status_code,

                "response_time": response_time,

                "response_size": content_length,

                "json": response_json,

                "headers": dict(response.headers),

                "content_type": response.headers.get(
                    "content-type",
                    "unknown"
                )
            }

        except httpx.ConnectTimeout:

            return {
                "success": False,
                "error": "Connection timeout"
            }

        except httpx.ReadTimeout:

            return {
                "success": False,
                "error": "Read timeout"
            }

        except httpx.ConnectError:

            return {
                "success": False,
                "error": "Unable to connect to endpoint"
            }

        except httpx.InvalidURL:

            return {
                "success": False,
                "error": "Invalid GraphQL endpoint URL"
            }

        except Exception as e:

            return {
                "success": False,
                "error": str(e)
            }
