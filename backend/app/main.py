from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.gzip import GZipMiddleware

from app.services.full_analyzer import analyzer
from app.api.v1.router import api_router
from app.api.v1.auth import router as auth_router
from app.core.xml_loader import config

import logging
import time
from datetime import datetime
import redis


# =========================================================
# 🔹 SAFE CONFIG
# =========================================================
def safe_get(section, key, default=None):
    try:
        return config.get(section, key)
    except Exception:
        return default


API_KEY = safe_get("security", "apiKey")
REDIS_URL = safe_get("redis", "url", "redis://localhost:6379")
RATE_LIMIT_MAX = int(
    safe_get("rateLimit", "requestsPerMinute", 60)
)


# =========================================================
# 🔹 LOGGING
# =========================================================
logging.basicConfig(level=logging.INFO)

logger = logging.getLogger("trust_edge")


# =========================================================
# 🔹 REDIS CONNECTION
# =========================================================
redis_client = None

try:
    redis_client = redis.from_url(
        REDIS_URL,
        decode_responses=True
    )

    redis_client.ping()

    logger.info("✅ Redis connected")

except Exception as e:

    logger.warning(f"⚠️ Redis unavailable: {e}")


# =========================================================
# 🔹 FASTAPI APP
# =========================================================
app = FastAPI(
    title="Trust_Edge API Security Analyzer",
    description="Enterprise API Security Testing Platform",
    version="2.0.0"
)


# =========================================================
# 🔹 CORS MIDDLEWARE
# =========================================================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Change in production
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
class RedisRateLimitMiddleware(BaseHTTPMiddleware):

    async def dispatch(self, request: Request, call_next):

        if not redis_client:
            return await call_next(request)

        ip = request.client.host

        key = f"rate_limit:{ip}"

        try:
            count = redis_client.incr(key)

            if count == 1:
                redis_client.expire(key, 60)

            if count > RATE_LIMIT_MAX:

                return JSONResponse(
                    status_code=429,
                    content={
                        "success": False,
                        "detail": "Rate limit exceeded"
                    }
                )

        except Exception:
            pass

        return await call_next(request)


app.add_middleware(RedisRateLimitMiddleware)


# =========================================================
# 🔹 REQUEST SIZE LIMIT
# =========================================================
@app.middleware("http")
async def limit_request_size(
    request: Request,
    call_next
):

    body = await request.body()

    if len(body) > 2 * 1024 * 1024:

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

    response.headers.update({
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "X-XSS-Protection": "1; mode=block",
        "Referrer-Policy": "no-referrer",
        "Strict-Transport-Security":
            "max-age=31536000; includeSubDomains"
    })

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
        "/health",
        "/docs",
        "/redoc",
        "/openapi.json"
    ]

    if request.url.path in excluded_paths:
        return await call_next(request)

    if API_KEY:

        incoming_key = request.headers.get("x-api-key")

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
# 🔹 ROOT HEALTH ROUTE
# =========================================================
@app.get("/")
async def root():

    return {
        "success": True,
        "service": "Trust_Edge API",
        "version": "2.0.0",
        "status": "running",
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
            redis_status = redis_client.ping()
    except Exception:
        redis_status = False

    return {
        "success": True,
        "status": "healthy",
        "redis": redis_status,
        "analyzer": "ready",
        "timestamp": datetime.utcnow().isoformat()
    }


# =========================================================
# 🔹 MAIN API ROUTERS
# =========================================================
app.include_router(
    api_router,
    prefix="/api/v1"
)


# =========================================================
# 🔹 AUTH ROUTES
# =========================================================
app.include_router(
    auth_router,
    prefix="/api/v1/auth"
)


# =========================================================
# 🔹 ANALYZER ENDPOINT
# =========================================================
@app.post("/api/v1/analyze")
async def analyze_api(data: dict):

    try:

        result = analyzer.analyze_full_packet(
            data.get("request", {}),
            data.get("response", {})
        )

        return {
            "success": True,
            "timestamp": datetime.utcnow().isoformat(),
            "findings": result.get("findings", []),
            "overall_risk_score":
                result.get("overall_risk_score", 0),
            "severity":
                result.get("severity", "LOW"),
            "ai_suggestions":
                result.get("ai_suggestions", {}),
            "summary":
                result.get("summary")
        }

    except Exception as e:

        logger.error(
            f"Analyze endpoint error: {str(e)}"
        )

        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "detail": "Internal Server Error"
            }
        )
