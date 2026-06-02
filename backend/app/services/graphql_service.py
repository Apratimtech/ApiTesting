from app.graphql.graphql_client import GraphQLClient
from app.graphql.graphql_security import (
    GraphQLSecurityAnalyzer
)


class GraphQLService:

    @staticmethod
    async def process_graphql_request(payload):

        try:

            # =============================================
            # HEADERS
            # =============================================

            headers = payload.headers or {}

            # =============================================
            # EXECUTE GRAPHQL REQUEST
            # =============================================

            result = await GraphQLClient.execute(

                endpoint=payload.endpoint,

                query=payload.query,

                variables=payload.variables or {},

                headers=headers,

                auth_type=payload.auth_type,

                auth_value=payload.auth_value
            )

            # =============================================
            # REQUEST FAILED
            # =============================================

            if not result.get("success"):

                return {
                    "success": False,

                    "status_code": 500,

                    "response_time": 0,

                    "response": {},

                    "findings": [],

                    "risk_score": 0,

                    "analysis": None,

                    "metrics": None,

                    "headers": {},

                    "error": result.get(
                        "error",
                        "Unknown error"
                    )
                }

            # =============================================
            # SECURITY ANALYSIS
            # =============================================

            (
                risk_score,
                findings,
                analysis
            ) = GraphQLSecurityAnalyzer.analyze(

                query=payload.query,

                headers=headers,

                response_json=result["json"]
            )

            # =============================================
            # METRICS
            # =============================================

            metrics = {

                "query_depth":
                    GraphQLSecurityAnalyzer.calculate_depth(
                        payload.query
                    ),

                "query_size":
                    len(payload.query),

                "alias_count":
                    len(
                        __import__("re").findall(
                            r"\w+\s*:",
                            payload.query
                        )
                    ),

                "operation_count":
                    len(
                        __import__("re").findall(
                            r"\b(query|mutation)\b",
                            payload.query.lower()
                        )
                    ),

                "introspection_detected":
                    "__schema"
                    in payload.query.lower(),

                "sensitive_data_detected":
                    any(
                        field.lower()
                        in str(result["json"]).lower()

                        for field in
                        GraphQLSecurityAnalyzer.SENSITIVE_FIELDS
                    ),

                "injection_detected":
                    any(
                        pattern
                        in payload.query.lower()

                        for pattern in [
                            "union select",
                            "$ne",
                            "<script>"
                        ]
                    )
            }

            # =============================================
            # FINAL RESPONSE
            # =============================================

            return {

                "success": True,

                "status_code":
                    result["status_code"],

                "response_time":
                    result["response_time"],

                "response":
                    result["json"],

                "findings":
                    findings,

                "risk_score":
                    risk_score,

                "analysis":
                    analysis,

                "metrics":
                    metrics,

                "headers":
                    result["headers"],

                "content_type":
                    result.get(
                        "content_type",
                        "unknown"
                    ),

                "response_size":
                    result.get(
                        "response_size",
                        0
                    )
            }

        except Exception as e:

            return {

                "success": False,

                "status_code": 500,

                "response_time": 0,

                "response": {},

                "findings": [],

                "risk_score": 0,

                "analysis": None,

                "metrics": None,

                "headers": {},

                "error": str(e)
            }
