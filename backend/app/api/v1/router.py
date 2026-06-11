from fastapi import APIRouter
from fastapi.responses import JSONResponse
from datetime import datetime
from app.api.v1.endpoints import (
    request,
    analyze,
    collections,
    history
)
from app.mqtt.router import (
    router as mqtt_router
)

# =========================================================
# 🔹 MAIN API ROUTER - FIXED (No double prefix)
# =========================================================
api_router = APIRouter()   # ← NO prefix here (fixed)

# =========================================================
# 🔹 HEALTH CHECK ENDPOINT
# =========================================================
@api_router.get(
    "/",
    tags=["Health"]
)
async def health_check():
    return JSONResponse(
        status_code=200,
        content={
            "success": True,
            "status": "healthy",
            "service": "TrustEdge API",
            "version": "v1",
            "timestamp": datetime.utcnow().isoformat()
        }
    )

# =========================================================
# 🔹 REQUEST ROUTER
# =========================================================
api_router.include_router(
    request.router,
    prefix="/request",
    tags=["Request"]
)

# =========================================================
# 🔹 ANALYZER ROUTER
# =========================================================
api_router.include_router(
    analyze.router,
    prefix="/analyze",
    tags=["Analyzer"]
)

# =========================================================
# 🔹 COLLECTION ROUTER
# =========================================================
api_router.include_router(
    collections.router,
    prefix="/collections",
    tags=["Collections"]
)

# =========================================================
# 🔹 HISTORY ROUTER
# =========================================================
api_router.include_router(
    history.router,
    prefix="/history",
    tags=["History"]
)

# =========================================================
# 🔹 MQTT ROUTER
# =========================================================
api_router.include_router(
    mqtt_router
)

