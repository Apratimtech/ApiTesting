import logging

from typing import Dict, Any, List

from sqlalchemy.orm import Session

from app.models.analyzer import (
    AnalyzerScan,
    AnalyzerFinding,
    AnalyzerRequest,
    AnalyzerResponse,
)

# =========================================================
# LOGGER
# =========================================================

logger = logging.getLogger("TrustEdgeStorage")


# =========================================================
# STORAGE SERVICE
# =========================================================

class AnalyzerStorageService:

    """
    Enterprise storage service for saving:
    - scans
    - findings
    - request data
    - response data
    """

    # =====================================================
    # MAIN SAVE FUNCTION
    # =====================================================

    def save_analysis(
        self,
        db: Session,
        request_data: Dict[str, Any],
        response_data: Dict[str, Any],
        analysis_result: Dict[str, Any],
    ) -> int:

        try:

            print("SAVE_ANALYSIS STARTED")

            # =================================================
            # MAIN SCAN
            # =================================================

            scan = AnalyzerScan(

                url=request_data.get(
                    "url",
                    "",
                ),

                method=request_data.get(
                    "method",
                    "GET",
                ),

                severity=analysis_result.get(
                    "severity",
                    "LOW",
                ),

                overall_risk_score=analysis_result.get(
                    "overall_risk_score",
                    0,
                ),

                success=analysis_result.get(
                    "success",
                    True,
                ),

                summary=analysis_result.get(
                    "summary",
                    "",
                ),

                generated_by=analysis_result.get(
                    "generated_by",
                    "TrustEdge Analyzer",
                ),
            )

            db.add(scan)

            # =================================================
            # FLUSH TO GET scan.id
            # =================================================

            db.flush()

            print(f"SCAN CREATED: {scan.id}")

            # =================================================
            # SAVE REQUEST
            # =================================================

            request_row = AnalyzerRequest(

                scan_id=scan.id,

                url=request_data.get(
                    "url"
                ),

                method=request_data.get(
                    "method"
                ),

                headers=request_data.get(
                    "headers",
                    {},
                ),

                body=request_data.get(
                    "body"
                ),

                body_type=request_data.get(
                    "bodyType"
                ),
            )

            db.add(request_row)

            # =================================================
            # SAVE RESPONSE
            # =================================================

            response_row = AnalyzerResponse(

                scan_id=scan.id,

                status_code=response_data.get(
                    "status"
                ),

                headers=response_data.get(
                    "headers",
                    {},
                ),

                body=response_data.get(
                    "body"
                ),

                raw_text=response_data.get(
                    "rawText"
                ),
            )

            db.add(response_row)

            # =================================================
            # SAVE FINDINGS
            # =================================================

            findings: List[Dict[str, Any]] = analysis_result.get(
                "findings",
                [],
            )

            for finding in findings:

                finding_row = AnalyzerFinding(

                    scan_id=scan.id,

                    issue=finding.get(
                        "issue",
                        "Unknown Issue",
                    ),

                    description=finding.get(
                        "description",
                        "",
                    ),

                    severity=finding.get(
                        "severity",
                        "LOW",
                    ),

                    category=finding.get(
                        "category",
                        "General",
                    ),

                    recommendation=finding.get(
                        "recommendation",
                        "",
                    ),

                    cwe=finding.get(
                        "cwe",
                        "",
                    ),
                )

                db.add(finding_row)

            # =================================================
            # FINAL COMMIT
            # =================================================

            print("BEFORE DB COMMIT")

            db.commit()

            print("AFTER DB COMMIT")

            db.refresh(scan)

            logger.info(
                f"Analysis saved successfully: {scan.id}"
            )

            return scan.id

        except Exception as e:

            db.rollback()

            print("DATABASE ERROR:", str(e))

            logger.exception(
                f"Storage failure: {str(e)}"
            )

            raise


# =========================================================
# SINGLETON INSTANCE
# =========================================================

analyzer_storage = AnalyzerStorageService()

