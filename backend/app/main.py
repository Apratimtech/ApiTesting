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

# -------------------------
# SAFE CONFIG
# -------------------------
def safe_get(section, key, default=None):
    try:
        return config.get(section, key)
    except Exception:
        return default

API_KEY = safe_get("security", "apiKey")
REDIS_URL = safe_get("redis", "url", "redis://localhost:6379")
RATE_LIMIT_MAX = int(safe_get("rateLimit", "requestsPerMinute", 60))

# -------------------------
# LOGGING
# -------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("trust_edge")

# -------------------------
# REDIS (Optional)
# -------------------------
redis_client = None
try:
    redis_client = redis.from_url(REDIS_URL, decode_responses=True)
    redis_client.ping()
    logger.info("✅ Redis connected")
except Exception as e:
    logger.warning(f"⚠️ Redis unavailable: {e}")

# -------------------------
# APP
# -------------------------
app = FastAPI(
    title="Trust_Edge API Security Analyzer",
    version="2.0"
)

# -------------------------
# MIDDLEWARE
# -------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # change in production
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(GZipMiddleware, minimum_size=1000)


# -------------------------
# RATE LIMIT MIDDLEWARE
# -------------------------
class RedisRateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if not redis_client:
            return await call_next(request)

        ip = request.client.host
        key = f"rate:{ip}"

        try:
            count = redis_client.incr(key)
            if count == 1:
                redis_client.expire(key, 60)

            if count > RATE_LIMIT_MAX:
                return JSONResponse(
                    status_code=429,
                    content={"success": False, "detail": "Rate limit exceeded"}
                )
        except Exception:
            pass

        return await call_next(request)


app.add_middleware(RedisRateLimitMiddleware)


# -------------------------
# REQUEST SIZE LIMIT
# -------------------------
@app.middleware("http")
async def limit_size(request: Request, call_next):
    body = await request.body()

    if len(body) > 2 * 1024 * 1024:  # 2MB
        return JSONResponse(
            status_code=413,
            content={"success": False, "detail": "Request too large"}
        )

    return await call_next(request)


# -------------------------
# SECURITY HEADERS
# -------------------------
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)

    response.headers.update({
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "X-XSS-Protection": "1; mode=block",
        "Referrer-Policy": "no-referrer",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains"
    })

    return response


# -------------------------
# API KEY CHECK
# -------------------------
@app.middleware("http")
async def check_api_key(request: Request, call_next):
    if request.url.path in ["/health", "/docs", "/redoc"]:
        return await call_next(request)

    if API_KEY:
        if request.headers.get("x-api-key") != API_KEY:
            return JSONResponse(
                status_code=401,
                content={"success": False, "detail": "Invalid API Key"}
            )

    return await call_next(request)


# -------------------------
# LOGGING MIDDLEWARE
# -------------------------
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.time()

    response = await call_next(request)

    duration = round(time.time() - start, 3)
    logger.info(f"{request.method} {request.url.path} → {response.status_code} ({duration}s)")

    return response


# -------------------------
# ROUTES
# -------------------------
app.include_router(api_router, prefix="/api/v1")

# ✅ FIXED: Proper auth route prefix
app.include_router(auth_router, prefix="/api/v1/auth")


# -------------------------
# HEALTH CHECK
# -------------------------
@app.get("/health")
async def health():
    return {
        "status": "ok",
        "redis": bool(redis_client and redis_client.ping()),
        "analyzer": "ready",
        "time": datetime.utcnow().isoformat()
    }


# -------------------------
# MAIN ANALYZER
# -------------------------
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
            "overall_risk_score": result.get("overall_risk_score", 0),
            "severity": result.get("severity", "LOW"),
            "ai_suggestions": result.get("ai_suggestions", {}),
            "summary": result.get("summary")
        }

    except Exception as e:
        logger.error(f"Analyze endpoint error: {e}")

        return JSONResponse(
            status_code=500,
            content={"success": False, "detail": "Internal Server Error"}
        )
