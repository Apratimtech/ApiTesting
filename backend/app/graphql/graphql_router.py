from fastapi import APIRouter
from fastapi.responses import JSONResponse

import logging
from datetime import datetime

from app.graphql.graphql_models import (
    GraphQLRequest
)

from app.graphql.graphql_handler import (
    GraphQLHandler
)

# =========================================================
# LOGGER
# =========================================================

logger = logging.getLogger("GraphQLRouter")

# =========================================================
# ROUTER
# =========================================================

router = APIRouter(

    prefix="/graphql",

    tags=["GraphQL Security Console"]
)

# =========================================================
# GRAPHQL EXECUTION ENDPOINT
# =========================================================

@router.post("/execute")
async def execute_graphql(
    payload: GraphQLRequest
):

    try:

        logger.info(
            "Incoming GraphQL execution request"
        )

        result = await (
            GraphQLHandler.handle(payload)
        )

        return result

    except Exception as e:

        logger.error(
            f"Router failure: {str(e)}"
        )

        return JSONResponse(

            status_code=500,

            content={

                "success": False,

                "timestamp":
                    datetime.utcnow().isoformat(),

                "error":
                    "GraphQL router failed",

                "details":
                    str(e)
            }
        )

# =========================================================
# HEALTH CHECK ENDPOINT
# =========================================================

@router.get("/health")

async def graphql_health():

    return {

        "success": True,

        "service":
            "GraphQL Security Scanner",

        "status":
            "healthy",

        "timestamp":
            datetime.utcnow().isoformat()
    }

# =========================================================
# VERSION ENDPOINT
# =========================================================

@router.get("/version")

async def graphql_version():

    return {

        "success": True,

        "version":
            "1.0.0",

        "engine":
            "TrustEdge GraphQL Security Engine",

        "features": [

            "OWASP API Security",

            "GraphQL Introspection Detection",

            "Sensitive Data Exposure Detection",

            "Alias Abuse Detection",

            "Deep Query Analysis",

            "Mutation Abuse Detection",

            "SSRF Protection",

            "Security Metrics"
        ]
    }
