from fastapi import APIRouter, status
from app.services.storage import storage

router = APIRouter(
    prefix="/history",
    tags=["History"]
)


# =========================================================
# 🔹 GET ALL REQUEST HISTORY
# =========================================================
@router.get("/", status_code=status.HTTP_200_OK)
async def get_history():

    history_records = storage.get_history()

    return {
        "success": True,
        "count": len(history_records),
        "data": history_records
    }
