from fastapi import APIRouter, HTTPException, status
from uuid import uuid4
from datetime import datetime

from app.schemas.analyzer import AnalyzeRequest
from app.services.api_executor import execute_request
from app.services.storage import history_db

router = APIRouter(
    prefix="/analyzer",
    tags=["Analyzer"]
)


# =========================================================
# 🔹 EXECUTE API REQUEST
# =========================================================
@router.post("/")
async def analyze_request(data: AnalyzeRequest):

    try:

        # -------------------------------------------------
        # Execute API Request
        # -------------------------------------------------
        result = await execute_request(
            method=data.method.value,
            url=str(data.url),
            headers=data.headers,
            body=data.body
        )

        # -------------------------------------------------
        # Create Execution History
        # -------------------------------------------------
        history_record = {
            "id": str(uuid4()),
            "request_id": data.id,
            "method": data.method.value,
            "url": str(data.url),
            "status": result.get("status"),
            "response": result.get("data"),
            "response_time": result.get("time"),
            "created_at": datetime.utcnow().isoformat()
        }

        history_db.append(history_record)

        # -------------------------------------------------
        # Final Structured Response
        # -------------------------------------------------
        return {
            "success": True,
            "message": "API request executed successfully",
            "data": result
        }

    except Exception as e:

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )
