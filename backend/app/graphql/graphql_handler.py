from fastapi import HTTPException
from fastapi.responses import JSONResponse

import traceback
import uuid
import logging

from datetime import datetime

# =========================================================
# CORRECT IMPORT
# =========================================================

from app.services.graphql_service import GraphQLService


# =========================================================
# LOGGER CONFIG
# =========================================================

logger = logging.getLogger("GraphQLHandler")


class GraphQLHandler:

    @staticmethod
    async def handle(payload):

        request_id = str(uuid.uuid4())

        request_start = datetime.utcnow()

        try:

            logger.info(
                f"[{request_id}] Incoming GraphQL request"
            )

            # =================================================
            # PROCESS GRAPHQL REQUEST
            # =================================================

            result = await GraphQLService.process_graphql_request(
                payload
            )

            # =================================================
            # FAILED RESPONSE
            # =================================================

            if not result.get("success"):

                logger.error(
                    f"[{request_id}] GraphQL request failed"
                )

                return JSONResponse(

                    status_code=result.get(
                        "status_code",
                        500
                    ),

                    content={

                        "success": False,

                        "request_id": request_id,

                        "timestamp":
                            datetime.utcnow().isoformat(),

                        "error":
                            result.get(
                                "error",
                                "GraphQL request failed"
                            ),

                        "details":
                            result.get(
                                "details",
                                None
                            )
                    }
                )

            # =================================================
            # SUCCESS RESPONSE
            # =================================================

            logger.info(
                f"[{request_id}] GraphQL request completed successfully"
            )

            return {

                "success": True,

                "request_id": request_id,

                "timestamp":
                    datetime.utcnow().isoformat(),

                "status_code":
                    result.get(
                        "status_code",
                        200
                    ),

                "response_time":
                    result.get(
                        "response_time",
                        0
                    ),

                "response_size":
                    result.get(
                        "response_size",
                        0
                    ),

                "content_type":
                    result.get(
                        "content_type",
                        "application/json"
                    ),

                # =========================================
                # PURE GRAPHQL RESPONSE
                # =========================================

                "response":
                    result.get(
                        "response",
                        {}
                    ),

                # =========================================
                # SECURITY FINDINGS
                # =========================================

                "findings":
                    result.get(
                        "findings",
                        []
                    ),

                "risk_score":
                    result.get(
                        "risk_score",
                        0
                    ),

                # =========================================
                # ANALYSIS
                # =========================================

                "analysis":
                    result.get(
                        "analysis",
                        {}
                    ),

                # =========================================
                # SECURITY METRICS
                # =========================================

                "metrics":
                    result.get(
                        "metrics",
                        {}
                    ),

                # =========================================
                # RESPONSE HEADERS
                # =========================================

                "headers":
                    result.get(
                        "headers",
                        {}
                    )
            }

        # =====================================================
        # FASTAPI HTTP ERROR
        # =====================================================

        except HTTPException as http_error:

            logger.error(
                f"[{request_id}] HTTPException: "
                f"{str(http_error.detail)}"
            )

            raise http_error

        # =====================================================
        # UNEXPECTED SERVER ERROR
        # =====================================================

        except Exception as e:

            logger.critical(
                f"[{request_id}] Critical handler failure"
            )

            traceback.print_exc()

            return JSONResponse(

                status_code=500,

                content={

                    "success": False,

                    "request_id": request_id,

                    "timestamp":
                        datetime.utcnow().isoformat(),

                    "error":
                        "Internal Server Error",

                    "details":
                        str(e),

                    "trace":
                        traceback.format_exc()
                }
            )
