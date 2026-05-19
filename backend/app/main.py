# app/main.py
# =========================================================
# TRUST_EDGE ENTERPRISE CORE
# =========================================================

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.gzip import GZipMiddleware

from contextlib import asynccontextmanager

from app.services.full_analyzer import analyzer
from app.api.v1.router import api_router
from app.api.v1.auth import router as auth_router
from app.api.v1.grpc import router as grpc_router
from app.core.xml_loader import config

from app.grpc_proto.grpc_server import serve

# =========================================================
# MQTT ROUTER IMPORT
# =========================================================

from app.mqtt.router import router as mqtt_router

import logging
import time
import asyncio
from datetime import datetime
import redis.asyncio as redis


# =========================================================
# 🔹 SAFE CONFIG
# =========================================================

def safe_get(section, key, default=None):

    try:
        return config.get(section, key)

    except Exception:
        return default


API_KEY = safe_get(
    "security",
    "apiKey"
)

REDIS_URL = safe_get(
    "redis",
    "url",
    "redis://localhost:6379"
)

RATE_LIMIT_MAX = int(
    safe_get(
        "rateLimit",
        "requestsPerMinute",
        60
    )
)

MAX_REQUEST_SIZE = 2 * 1024 * 1024


# =========================================================
# 🔹 LOGGING
# =========================================================

logging.basicConfig(
    level=logging.INFO,
    format=(
        "%(asctime)s | "
        "%(levelname)s | "
        "%(name)s | "
        "%(message)s"
    )
)

logger = logging.getLogger("trust_edge")


# =========================================================
# 🔹 REDIS CONNECTION
# =========================================================

redis_client = None


async def initialize_redis():

    global redis_client

    try:

        redis_client = redis.from_url(
            REDIS_URL,
            decode_responses=True
        )

        await redis_client.ping()

        logger.info("✅ Redis connected")

    except Exception as e:

        logger.warning(
            f"⚠️ Redis unavailable: {e}"
        )

        redis_client = None


# =========================================================
# 🔹 gRPC TASK STATE
# =========================================================

grpc_server_task = None


# =========================================================
# 🔹 APPLICATION LIFESPAN
# =========================================================

@asynccontextmanager
async def lifespan(app: FastAPI):

    global grpc_server_task

    logger.info("🚀 Starting Trust_Edge services...")

    # =====================================================
    # REDIS STARTUP
    # =====================================================

    await initialize_redis()

    # =====================================================
    # INTERNAL gRPC SERVER STARTUP
    # =====================================================

    try:

        grpc_server_task = asyncio.create_task(
            serve()
        )

        logger.info(
            "✅ Internal gRPC server started on :50051"
        )

    except Exception as e:

        logger.error(
            f"❌ Failed to start gRPC server: {e}"
        )

    logger.info("✅ Trust_Edge startup complete")

    yield

    # =====================================================
    # SHUTDOWN
    # =====================================================

    logger.info("🛑 Shutting down Trust_Edge...")

    try:

        if grpc_server_task:

            grpc_server_task.cancel()

            try:

                await grpc_server_task

            except asyncio.CancelledError:

                logger.info(
                    "✅ gRPC server stopped"
                )

        if redis_client:

            await redis_client.close()

            logger.info(
                "✅ Redis connection closed"
            )

    except Exception as e:

        logger.warning(
            f"Shutdown warning: {e}"
        )

    logger.info(
        "✅ Trust_Edge shutdown complete"
    )


# =========================================================
# 🔹 FASTAPI APP
# =========================================================

app = FastAPI(
    title="Trust_Edge API Security Analyzer",
    description="Enterprise API Security Testing Platform",
    version="5.0.0",
    lifespan=lifespan
)


# =========================================================
# 🔹 TRUSTED HOST MIDDLEWARE
# =========================================================

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=[
        "localhost",
        "127.0.0.1",
        "*"
    ]
)


# =========================================================
# 🔹 CORS MIDDLEWARE
# =========================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================================================
# 🔹 GZIP COMPRESSION
# =========================================================

app.add_middleware(
    GZipMiddleware,
    minimum_size=1000
)


# =========================================================
# 🔹 RATE LIMIT MIDDLEWARE
# =========================================================

class RedisRateLimitMiddleware(
    BaseHTTPMiddleware
):

    async def dispatch(
        self,
        request: Request,
        call_next
    ):

        if not redis_client:
            return await call_next(request)

        try:

            ip = request.client.host

            key = f"rate_limit:{ip}"

            count = await redis_client.incr(key)

            if count == 1:

                await redis_client.expire(
                    key,
                    60
                )

            if count > RATE_LIMIT_MAX:

                return JSONResponse(
                    status_code=429,
                    content={
                        "success": False,
                        "detail": "Rate limit exceeded"
                    }
                )

        except Exception as e:

            logger.warning(
                f"Rate limit middleware error: {e}"
            )

        return await call_next(request)


app.add_middleware(
    RedisRateLimitMiddleware
)


# =========================================================
# 🔹 REQUEST SIZE LIMIT
# =========================================================

@app.middleware("http")
async def limit_request_size(
    request: Request,
    call_next
):

    body = await request.body()

    if len(body) > MAX_REQUEST_SIZE:

        return JSONResponse(
            status_code=413,
            content={
                "success": False,
                "detail": "Request too large"
            }
        )

    return await call_next(request)


# =========================================================
# 🔹 SECURITY HEADERS
# =========================================================

@app.middleware("http")
async def add_security_headers(
    request: Request,
    call_next
):

    response = await call_next(request)

    response.headers[
        "X-Frame-Options"
    ] = "DENY"

    response.headers[
        "X-Content-Type-Options"
    ] = "nosniff"

    response.headers[
        "X-XSS-Protection"
    ] = "1; mode=block"

    response.headers[
        "Referrer-Policy"
    ] = "no-referrer"

    response.headers[
        "Strict-Transport-Security"
    ] = (
        "max-age=31536000; includeSubDomains"
    )

    response.headers[
        "Content-Security-Policy"
    ] = "default-src 'self'"

    response.headers[
        "Server"
    ] = "TrustEdge"

    return response


# =========================================================
# 🔹 API KEY VALIDATION
# =========================================================

@app.middleware("http")
async def validate_api_key(
    request: Request,
    call_next
):

    excluded_paths = [
        "/",
        "/health",
        "/docs",
        "/redoc",
        "/openapi.json",
        "/api/analyze",
        "/api/v1/analyze",
    ]

    current_path = request.url.path

    if (
        current_path in excluded_paths
        or current_path.startswith("/docs")
        or current_path.startswith("/redoc")
    ):
        return await call_next(request)

    if API_KEY:

        incoming_key = request.headers.get(
            "x-api-key"
        )

        if incoming_key != API_KEY:

            return JSONResponse(
                status_code=401,
                content={
                    "success": False,
                    "detail": "Invalid API Key"
                }
            )

    return await call_next(request)


# =========================================================
# 🔹 REQUEST LOGGING
# =========================================================

@app.middleware("http")
async def log_requests(
    request: Request,
    call_next
):

    start_time = time.time()

    response = await call_next(request)

    duration = round(
        time.time() - start_time,
        3
    )

    logger.info(
        f"{request.method} "
        f"{request.url.path} "
        f"-> {response.status_code} "
        f"({duration}s)"
    )

    return response


# =========================================================
# 🔹 GLOBAL ERROR HANDLER
# =========================================================

@app.exception_handler(Exception)
async def global_exception_handler(
    request: Request,
    exc: Exception
):

    logger.error(
        f"Unhandled error: {str(exc)}",
        exc_info=True
    )

    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "detail": "Internal Server Error"
        }
    )


# =========================================================
# 🔹 ROOT ROUTE
# =========================================================

@app.get("/")
async def root():

    return {
        "success": True,
        "service": "Trust_Edge API",
        "version": "5.0.0",
        "status": "running",
        "grpc": "active",
        "mqtt": "active",
        "timestamp": datetime.utcnow().isoformat()
    }


# =========================================================
# 🔹 HEALTH CHECK
# =========================================================

@app.get("/health")
async def health():

    redis_status = False

    try:

        if redis_client:

            redis_status = await redis_client.ping()

    except Exception:

        redis_status = False

    return {
        "success": True,
        "status": "healthy",
        "redis": redis_status,
        "grpc": grpc_server_task is not None,
        "mqtt": True,
        "analyzer": "ready",
        "timestamp": datetime.utcnow().isoformat()
    }


# =========================================================
# 🔹 API ROUTERS
# =========================================================

app.include_router(
    api_router
)

app.include_router(
    auth_router,
    prefix="/api/v1/auth"
)

app.include_router(
    grpc_router
)

app.include_router(
    mqtt_router,
    prefix="/api/v1"
)


# =========================================================
# 🔹 ANALYZER ENDPOINT
# =========================================================

@app.post("/api/analyze")
@app.post("/api/v1/analyze")
async def analyze_api(data: dict):

    try:

        request_data = data.get(
            "request",
            {}
        )

        response_data = data.get(
            "response",
            {}
        )

        # =====================================================
        # SECURITY ANALYSIS
        # =====================================================

        result = analyzer.analyze_full_packet(
            request_data,
            response_data
        )

        # =====================================================
        # NORMAL RESPONSE TAB DATA
        # =====================================================

        normal_response = {
            "status": "SUCCESS",
            "code": 0,
            "message": "Request processed successfully",
            "data": request_data,
            "server_metadata": {
                "processed_by": "trust-edge-engine",
                "execution_time": "42ms",
                "tls_enabled": True,
                "streaming": False,
            },
        }

        # =====================================================
        # FINAL RESPONSE
        # =====================================================

        return {
            "success": True,
            "timestamp": datetime.utcnow().isoformat(),

            # RESPONSE TAB
            "response": normal_response,

            # SECURITY TAB
            "findings": result.get(
                "findings",
                []
            ),

            "overall_risk_score": result.get(
                "overall_risk_score",
                0
            ),

            "severity": result.get(
                "severity",
                "LOW"
            ),

            "ai_suggestions": result.get(
                "ai_suggestions",
                {}
            ),

            "summary": result.get(
                "summary"
            )
        }

    except Exception as e:

        logger.error(
            f"Analyze endpoint error: {str(e)}",
            exc_info=True
        )

        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "detail": "Internal Server Error"
            }
        )
