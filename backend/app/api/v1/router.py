from fastapi import APIRouter
from app.api.v1.endpoints import request, analyze

api_router = APIRouter()

@api_router.get("/", tags=["Health"])
async def root():
    return {
        "status": "ok",
        "message": "TrustEdge API is running"
    }

api_router.include_router(request.router, prefix="/request", tags=["Request"])
api_router.include_router(analyze.router, prefix="/analyze", tags=["Analyzer"])
