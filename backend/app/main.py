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
from app.services.analyzer_storage import analyzer_storage
from app.db.postgres import SessionLocal
from app.api.v1.router import api_router
from app.api.v1.auth import router as auth_router
from app.api.v1.grpc import router as grpc_router
from app.graphql.graphql_router import router as graphql_router
from app.mqtt.router import router as mqtt_router
from app.ml.router import router as ml_router
from app.core.xml_loader import config
from app.grpc_proto.grpc_server import serve
import logging
import time
import asyncio
import app.models.sidebar
import traceback
from datetime import datetime
import redis.asyncio as redis

# =========================================================
# SAFE CONFIG
# =========================================================
def safe_get(section, key, default=None):
    try:
        return config.get(section, key)
    except Exception:
        return default

API_KEY = safe_get("security", "apiKey")
REDIS_URL = safe_get("redis", "url", "redis://localhost:6379")
RATE_LIMIT_MAX = int(safe_get("rateLimit", "requestsPerMinute", 60) or 60)
MAX_REQUEST_SIZE = 2 * 1024 * 1024

# =========================================================
# LOGGING
# =========================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s"
)
logger = logging.getLogger("trust_edge")

# =========================================================
# REDIS CONNECTION
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
        logger.info("Redis connected")
    except Exception as e:
        logger.warning(f"Redis unavailable: {e}")
        redis_client = None

# =========================================================
# gRPC SUPERVISED
# =========================================================
grpc_server_task = None

async def safe_grpc_server():
    while True:
        try:
            await serve()
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"gRPC crashed: {e}", exc_info=True)
            await asyncio.sleep(5)

# =========================================================
# APPLICATION LIFESPAN
# =========================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    global grpc_server_task
    logger.info("Starting Trust_Edge services...")
    await initialize_redis()
    try:
        grpc_server_task = asyncio.create_task(safe_grpc_server())
        logger.info("Internal gRPC server started on :50051")
    except Exception as e:
        logger.error(f"Failed to start gRPC server: {e}")
    logger.info("Trust_Edge startup complete")
    yield
    logger.info("Shutting down Trust_Edge...")
    try:
        if grpc_server_task:
            grpc_server_task.cancel()
            try:
                await grpc_server_task
            except asyncio.CancelledError:
                logger.info("gRPC server stopped")
        if redis_client:
            await redis_client.close()
            logger.info("Redis connection closed")
    except Exception as e:
        logger.warning(f"Shutdown warning: {e}")
    logger.info("Trust_Edge shutdown complete")

# =========================================================
# FASTAPI APP
# =========================================================
app = FastAPI(
    title="Trust_Edge API Security Analyzer",
    description="Enterprise API Security Testing Platform",
    version="5.0.1",
    lifespan=lifespan
)

# =========================================================
# MIDDLEWARE
# =========================================================
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["localhost", "127.0.0.1", "*"]
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Rate Limit Middleware
class RedisRateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if not redis_client:
            return await call_next(request)
        try:
            ip = request.client.host
            key = f"rate_limit:{ip}"
            count = await redis_client.incr(key)
            if count == 1:
                await redis_client.expire(key, 60)
            if count > RATE_LIMIT_MAX:
                return JSONResponse(status_code=429, content={
                    "success": False, "detail": "Rate limit exceeded"
                })
        except Exception as e:
            logger.warning(f"Rate limit middleware error: {e}")
        return await call_next(request)

app.add_middleware(RedisRateLimitMiddleware)

# Request Size Limit
@app.middleware("http")
async def limit_request_size(request: Request, call_next):
    body = await request.body()
    if len(body) > MAX_REQUEST_SIZE:
        return JSONResponse(status_code=413, content={
            "success": False, "detail": "Request too large"
        })
    return await call_next(request)

# Security Headers
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["Server"] = "TrustEdge"
    return response

# =========================================================
# API KEY VALIDATION - UPDATED EXEMPTIONS
# =========================================================
@app.middleware("http")
async def validate_api_key(request: Request, call_next):
    excluded_paths = [
        "/",
        "/health",
        "/docs",
        "/redoc",
        "/openapi.json",
        "/graphql",
        "/api/v1/analyze"
    ]
    current_path = request.url.path

    # 🔥 Exempt Frontend Read APIs (Collections, MQTT, History)
    if (
        current_path.startswith("/api/v1/collections")
        or current_path.startswith("/api/v1/mqtt")
        or current_path.startswith("/api/v1/history")
    ):
        return await call_next(request)

    if (current_path in excluded_paths or
        current_path.startswith("/docs") or
        current_path.startswith("/redoc") or
        current_path.startswith("/graphql")):
        return await call_next(request)

    if API_KEY:
        incoming_key = request.headers.get("x-api-key")
        if incoming_key != API_KEY:
            return JSONResponse(status_code=401, content={
                "success": False,
                "detail": "Invalid API Key"
            })
    return await call_next(request)

# Request Logging
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    duration = round(time.time() - start_time, 3)
    logger.info(f"{request.method} {request.url.path} -> {response.status_code} ({duration}s)")
    return response

# Global Error Handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    traceback.print_exc()
    logger.error(f"Unhandled error: {str(exc)}", exc_info=True)
    return JSONResponse(status_code=500, content={
        "success": False, "detail": str(exc)
    })

# =========================================================
# BASIC ROUTES
# =========================================================
@app.get("/")
async def root():
    return {
        "success": True,
        "service": "Trust_Edge API",
        "version": "5.0.1",
        "status": "running",
        "grpc": "active",
        "mqtt": "active",
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/health")
async def health():
    redis_status = False
    try:
        if redis_client:
            redis_status = await redis_client.ping()
    except:
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
# API ROUTERS - FIXED PREFIX
# =========================================================
app.include_router(api_router, prefix="/api/v1")
app.include_router(auth_router, prefix="/api/v1/auth")
app.include_router(grpc_router)
app.include_router(graphql_router)
app.include_router(
    mqtt_router,
    prefix="/api/v1"
)
app.include_router(ml_router)

# =========================================================
# ANALYZER ENDPOINT
# =========================================================
@app.post("/api/v1/analyze")
async def analyze_api(data: dict):
    try:
        request_data = data.get("request") or {}
        response_data = data.get("response") or {}
        if not isinstance(request_data, dict): request_data = {}
        if not isinstance(response_data, dict): response_data = {}
        request_data.setdefault("headers", {})
        response_data.setdefault("headers", {})
        request_data.setdefault("body", "")
        response_data.setdefault("body", "")
        request_data.setdefault("method", "GET")
        request_data.setdefault("url", "")
        result = analyzer.analyze({
            "request": request_data,
            "response": response_data
        })
        db = SessionLocal()
        try:
            scan_id = analyzer_storage.save_analysis(
                db=db,
                request_data=request_data,
                response_data=response_data,
                analysis_result=result
            )
            db.commit()
            result["scan_id"] = scan_id
        finally:
            db.close()
        return result
    except Exception as e:
        traceback.print_exc()
        logger.error(f"Analyze endpoint error: {e}", exc_info=True)
        return JSONResponse(status_code=500, content={
            "success": False, "detail": str(e)
        })
