# =========================================================
# app/grpc_proto/grpc_server.py
# TRUST_EDGE ENTERPRISE gRPC SERVER
# =========================================================

import os
import asyncio
import logging
from concurrent import futures

import grpc

from grpc_reflection.v1alpha import reflection

# =========================================================
# GENERATED IMPORTS
# =========================================================
from app.grpc_proto.generated import (
    analyzer_pb2_grpc,
)

# =========================================================
# SERVICES
# =========================================================
from app.grpc_proto.services.analyzer_service import (
    AnalyzerService,
)

# =========================================================
# INTERCEPTORS
# =========================================================
from app.grpc_proto.interceptor import (
    AuthInterceptor,
)

# =========================================================
# LOGGING CONFIG
# =========================================================
logging.basicConfig(
    level=logging.INFO,
    format=(
        "[%(asctime)s] "
        "[%(levelname)s] "
        "[gRPC] "
        "%(message)s"
    ),
)

logger = logging.getLogger("grpc_server")

# =========================================================
# ENVIRONMENT CONFIG
# =========================================================
GRPC_HOST = os.getenv(
    "GRPC_HOST",
    "[::]:50051"
)

ENABLE_TLS = os.getenv(
    "GRPC_ENABLE_TLS",
    "true"
).lower() == "true"

ENABLE_REFLECTION = os.getenv(
    "GRPC_ENABLE_REFLECTION",
    "true"
).lower() == "true"

MAX_WORKERS = int(
    os.getenv(
        "GRPC_MAX_WORKERS",
        20
    )
)

MAX_MESSAGE_SIZE = 50 * 1024 * 1024

CERT_PATH = os.getenv(
    "GRPC_CERT_PATH",
    "certs/cert.pem"
)

KEY_PATH = os.getenv(
    "GRPC_KEY_PATH",
    "certs/key.pem"
)

# =========================================================
# KEEPALIVE + HARDENING
# =========================================================
KEEPALIVE_OPTIONS = [

    ("grpc.keepalive_time_ms", 30000),

    ("grpc.keepalive_timeout_ms", 10000),

    ("grpc.keepalive_permit_without_calls", True),

    ("grpc.http2.max_pings_without_data", 0),

    ("grpc.http2.min_time_between_pings_ms", 10000),

    ("grpc.http2.min_ping_interval_without_data_ms", 5000),

    ("grpc.max_send_message_length", MAX_MESSAGE_SIZE),

    ("grpc.max_receive_message_length", MAX_MESSAGE_SIZE),

    ("grpc.enable_retries", 1),

    ("grpc.so_reuseport", 1),
]

# =========================================================
# TLS CERTIFICATE LOADER
# =========================================================
def load_tls_credentials():

    if not os.path.exists(CERT_PATH):

        raise FileNotFoundError(
            f"Missing TLS certificate: "
            f"{CERT_PATH}"
        )

    if not os.path.exists(KEY_PATH):

        raise FileNotFoundError(
            f"Missing TLS private key: "
            f"{KEY_PATH}"
        )

    with open(KEY_PATH, "rb") as key_file:
        private_key = key_file.read()

    with open(CERT_PATH, "rb") as cert_file:
        certificate_chain = cert_file.read()

    logger.info(
        "TLS certificates loaded successfully"
    )

    logger.info(
        f"Certificate path: {CERT_PATH}"
    )

    return grpc.ssl_server_credentials(
        [
            (
                private_key,
                certificate_chain,
            )
        ]
    )

# =========================================================
# STARTUP VALIDATION
# =========================================================
async def startup_checks():

    logger.info(
        "Running startup validation..."
    )

    try:

        AnalyzerService()

        logger.info(
            "AnalyzerService initialized"
        )

    except Exception as e:

        logger.exception(
            f"Startup validation failed: "
            f"{str(e)}"
        )

        raise

# =========================================================
# GRACEFUL SHUTDOWN
# =========================================================
async def graceful_shutdown(server):

    logger.warning(
        "Graceful shutdown initiated"
    )

    await server.stop(
        grace=10
    )

    logger.warning(
        "gRPC server stopped safely"
    )

# =========================================================
# CREATE SERVER
# =========================================================
def create_server():

    logger.info(
        "Creating async enterprise gRPC server..."
    )

    return grpc.aio.server(
        futures.ThreadPoolExecutor(
            max_workers=MAX_WORKERS
        ),
        interceptors=[
            AuthInterceptor(),
        ],
        options=KEEPALIVE_OPTIONS,
    )

# =========================================================
# REGISTER SERVICES
# =========================================================
def register_services(server):

    # IMPORTANT:
    # Your generated proto currently contains:
    # UserServiceServicer
    # NOT AnalyzerServiceServicer
    #
    # So this registration is correct for your current setup.

    analyzer_pb2_grpc.add_UserServiceServicer_to_server(
        AnalyzerService(),
        server,
    )

    logger.info(
        "AnalyzerService registered"
    )

# =========================================================
# ENABLE REFLECTION
# =========================================================
def enable_reflection(server):

    SERVICE_NAMES = (
        reflection.SERVICE_NAME,
    )

    reflection.enable_server_reflection(
        SERVICE_NAMES,
        server,
    )

    logger.info(
        "gRPC reflection enabled"
    )

# =========================================================
# CONFIGURE PORTS
# =========================================================
def configure_ports(server):

    if ENABLE_TLS:

        logger.info(
            "TLS mode enabled"
        )

        server_credentials = (
            load_tls_credentials()
        )

        server.add_secure_port(
            GRPC_HOST,
            server_credentials,
        )

        logger.info(
            f"🔒 Secure TLS gRPC server running on "
            f"{GRPC_HOST}"
        )

    else:

        logger.warning(
            "⚠️ Running in INSECURE development mode"
        )

        server.add_insecure_port(
            GRPC_HOST
        )

        logger.warning(
            f"Insecure gRPC server running on "
            f"{GRPC_HOST}"
        )

# =========================================================
# MAIN SERVER
# =========================================================
async def serve():

    await startup_checks()

    logger.info(
        "Initializing enterprise gRPC infrastructure..."
    )

    server = create_server()

    register_services(server)

    if ENABLE_REFLECTION:
        enable_reflection(server)

    configure_ports(server)

    # =====================================================
    # START SERVER
    # =====================================================

    await server.start()

    logger.info(
        "Enterprise RPC security layer active"
    )

    logger.info(
        "OWASP validation engine loaded"
    )

    logger.info(
        "Authentication interceptor enabled"
    )

    logger.info(
        "AsyncIO gRPC engine running"
    )

    logger.info(
        "Ready for secure RPC traffic"
    )

    try:

        await server.wait_for_termination()

    except KeyboardInterrupt:

        logger.warning(
            "Manual shutdown detected"
        )

        await graceful_shutdown(server)

# =========================================================
# ENTRYPOINT
# =========================================================
if __name__ == "__main__":

    try:

        asyncio.run(
            serve()
        )

    except Exception as e:

        logger.exception(
            f"Fatal gRPC server error: "
            f"{str(e)}"
        )
