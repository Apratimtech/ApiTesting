from fastapi import HTTPException
from fastapi.responses import JSONResponse

import traceback
import uuid
import logging

from datetime import datetime

# =========================================================
# IMPORTS
# =========================================================

from app.services.graphql_service import GraphQLService
from app.services.analyzer_storage import analyzer_storage
from app.db.postgres import SessionLocal


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
            # SAVE ANALYSIS TO DATABASE
            # =================================================

            db = SessionLocal()

            try:

                analyzer_storage.save_analysis(
                    db=db,

                    request_data={
                        "url": getattr(
                            payload,
                            "endpoint",
                            None
                        ),

                        "method": "POST",

                        "protocol": "GRAPHQL",

                        "headers": getattr(
                            payload,
                            "headers",
                            {}
                        ),

                        "body": {
                            "query": getattr(
                                payload,
                                "query",
                                None
                            ),

                            "variables": getattr(
                                payload,
                                "variables",
                                {}
                            ),
                        },

                        "protocol_metadata": {
                            "auth_type": getattr(
                                payload,
                                "auth_type",
                                None
                            ),
                        }
                    },

                    response_data={
                        "status": result.get(
                            "status_code"
                        ),

                        "headers": result.get(
                            "headers",
                            {}
                        ),

                        "body": result.get(
                            "response",
                            {}
                        ),

                        "rawText": str(
                            result.get(
                                "response",
                                {}
                            )
                        ),

                        "success": result.get(
                            "success",
                            False
                        ),

                        "error": result.get(
                            "error"
                        ),

                        "details": result.get(
                            "details"
                        ),
                    },

                    analysis_result={

                        "success": result.get(
                            "success",
                            False
                        ),

                        "severity": result.get(
                            "severity",
                            "LOW"
                        ),

                        "overall_risk_score": result.get(
                            "risk_score",
                            0
                        ),

                        "summary": "GraphQL Analysis",

                        "generated_by": "Trust_Edge",

                        "analyzer_version": "2.5",

                        "findings": result.get(
                            "findings",
                            []
                        ),
                    }
                )

            except Exception as storage_error:

                logger.error(
                    f"[{request_id}] Failed to save analysis: "
                    f"{str(storage_error)}"
                )

            finally:
                db.close()

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

                "success": result.get(
                    "success",
                    True
                ),

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
