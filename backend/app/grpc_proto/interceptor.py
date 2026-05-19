import time
import logging
import hashlib

import grpc

# =========================================================
# LOGGING CONFIG
# =========================================================

logging.basicConfig(
    level=logging.INFO,
    format=(
        "[%(asctime)s] "
        "[%(levelname)s] "
        "[INTERCEPTOR] "
        "%(message)s"
    ),
)

logger = logging.getLogger(
    "grpc_auth"
)

# =========================================================
# SECURITY CONFIG
# =========================================================

VALID_API_KEYS = [
    "TRUSTEDGE_SECURE_KEY",
]

BLOCKED_IPS = [
    "192.168.1.100",
]

RATE_LIMIT_WINDOW = 60

RATE_LIMIT_MAX_REQUESTS = 100

REQUEST_TRACKER = {}

# =========================================================
# HELPER FUNCTIONS
# =========================================================

def get_client_ip(metadata):

    forwarded_ip = metadata.get(
        "x-forwarded-for"
    )

    real_ip = metadata.get(
        "x-real-ip"
    )

    if forwarded_ip:
        return forwarded_ip

    if real_ip:
        return real_ip

    return "unknown"


def hash_api_key(api_key: str):

    return hashlib.sha256(
        api_key.encode()
    ).hexdigest()[:16]


def check_rate_limit(client_id: str):

    current_time = time.time()

    if client_id not in REQUEST_TRACKER:

        REQUEST_TRACKER[client_id] = []

    REQUEST_TRACKER[client_id] = [
        ts
        for ts in REQUEST_TRACKER[client_id]
        if current_time - ts < RATE_LIMIT_WINDOW
    ]

    REQUEST_TRACKER[client_id].append(
        current_time
    )

    return (
        len(
            REQUEST_TRACKER[client_id]
        ) <= RATE_LIMIT_MAX_REQUESTS
    )

# =========================================================
# ENTERPRISE AUTH INTERCEPTOR
# =========================================================

class AuthInterceptor(
    grpc.aio.ServerInterceptor
):

    async def intercept_service(
        self,
        continuation,
        handler_call_details,
    ):

        start_time = time.time()

        metadata = dict(
            handler_call_details.invocation_metadata
        )

        method_name = (
            handler_call_details.method
        )

        client_ip = get_client_ip(
            metadata
        )

        api_key = metadata.get(
            "x-api-key"
        )

        user_agent = metadata.get(
            "user-agent",
            "unknown"
        )

        logger.info(
            f"Incoming RPC call: "
            f"{method_name}"
        )

        # =================================================
        # BLOCKED IP CHECK
        # =================================================

        if client_ip in BLOCKED_IPS:

            logger.warning(
                f"Blocked IP rejected: "
                f"{client_ip}"
            )

            async def deny_ip(
                request,
                context
            ):

                await context.abort(
                    grpc.StatusCode.PERMISSION_DENIED,
                    "Blocked IP Address",
                )

            return grpc.unary_unary_rpc_method_handler(
                deny_ip
            )

        # =================================================
        # API KEY VALIDATION
        # =================================================

        if not api_key:

            logger.warning(
                "Missing API Key"
            )

            async def deny_missing_key(
                request,
                context
            ):

                await context.abort(
                    grpc.StatusCode.UNAUTHENTICATED,
                    "Missing API Key",
                )

            return grpc.unary_unary_rpc_method_handler(
                deny_missing_key
            )

        if api_key not in VALID_API_KEYS:

            logger.warning(
                f"Invalid API Key attempt "
                f"from IP={client_ip}"
            )

            async def deny_invalid_key(
                request,
                context
            ):

                await context.abort(
                    grpc.StatusCode.UNAUTHENTICATED,
                    "Invalid API Key",
                )

            return grpc.unary_unary_rpc_method_handler(
                deny_invalid_key
            )

        # =================================================
        # RATE LIMIT CHECK
        # =================================================

        client_identifier = (
            f"{client_ip}:{api_key}"
        )

        if not check_rate_limit(
            client_identifier
        ):

            logger.warning(
                f"Rate limit exceeded "
                f"for {client_ip}"
            )

            async def deny_rate_limit(
                request,
                context
            ):

                await context.abort(
                    grpc.StatusCode.RESOURCE_EXHAUSTED,
                    "Rate Limit Exceeded",
                )

            return grpc.unary_unary_rpc_method_handler(
                deny_rate_limit
            )

        # =================================================
        # SUCCESSFUL AUTH
        # =================================================

        logger.info(
            f"Authenticated RPC Request | "
            f"Method={method_name} | "
            f"IP={client_ip} | "
            f"Agent={user_agent} | "
            f"APIKeyHash={hash_api_key(api_key)}"
        )

        handler = await continuation(
            handler_call_details
        )

        elapsed = round(
            (
                time.time() - start_time
            ) * 1000,
            2,
        )

        logger.info(
            f"RPC completed | "
            f"Method={method_name} | "
            f"Latency={elapsed}ms"
        )

        return handler
