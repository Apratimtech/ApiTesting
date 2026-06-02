import logging

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
)

from sqlalchemy.orm import Session

from app.db.postgres import get_db

from app.schemas.analyzer import AnalyzeRequest

from app.services.api_executor import (
    execute_request,
)

from app.services.full_analyzer import (
    analyzer,
)

from app.services.analyzer_storage import (
    analyzer_storage,
)

# =========================================================
# LOGGER
# =========================================================

logger = logging.getLogger(__name__)

# =========================================================
# ROUTER
# =========================================================

router = APIRouter(
    prefix="/analyzer",
    tags=["Analyzer"],
)

# =========================================================
# ANALYZE API
# =========================================================

@router.post("/")
async def analyze_request(
    data: AnalyzeRequest,
    db: Session = Depends(get_db),
):

    try:

        logger.info(
            f"Starting scan for: {data.url}"
        )

        # =================================================
        # EXECUTE TARGET API
        # =================================================

        response = await execute_request(
            method=data.method.value,
            url=str(data.url),
            headers=data.headers,
            body=data.body,
        )

        # =================================================
        # BUILD PAYLOAD
        # =================================================

        payload = {

            "request": {

                "method": data.method.value,

                "url": str(data.url),

                "headers": data.headers,

                "body": data.body,

                "bodyType": data.body_type,
            },

            "response": {

                "status": response.get(
                    "status"
                ),

                "headers": response.get(
                    "headers"
                ),

                "body": response.get(
                    "data"
                ),

                "rawText": str(
                    response.get("data")
                ),
            },
        }

        # =================================================
        # RUN SECURITY ANALYZER
        # =================================================

        analysis = analyzer.analyze(
            payload
        )

        # =================================================
        # SAVE TO DATABASE
        # =================================================

        scan_id = analyzer_storage.save_analysis(
            db=db,
            request_data=payload["request"],
            response_data=payload["response"],
            analysis_result=analysis,
        )

        logger.info(
            f"Scan completed successfully: {scan_id}"
        )

        # =================================================
        # FINAL RESPONSE
        # =================================================

        return {

            "success": True,

            "scan_id": scan_id,

            "analysis": analysis,
        }

    except HTTPException:

        raise

    except Exception as e:

        logger.exception(
            f"Analyzer failed: {str(e)}"
        )

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,

            detail="Internal analyzer error",
        )

