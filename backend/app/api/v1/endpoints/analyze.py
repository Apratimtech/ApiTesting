from fastapi import APIRouter, HTTPException
from datetime import datetime

from app.services.full_analyzer import TrustEdgeAnalyzer

router = APIRouter()

analyzer = TrustEdgeAnalyzer()


@router.post("/")
async def analyze_direct(data: dict):
    try:
        result = analyzer.analyze_full_packet(
            data.get("request", {}),
            data.get("response", {})
        )

        ai_data = result.get("ai_suggestions")

        # ✅ Fix list/dict issue
        if isinstance(ai_data, list):
            ai_data = ai_data[0] if ai_data else {}
        if not isinstance(ai_data, dict):
            ai_data = {}

        findings = result.get("findings", [])

        # -------------------------
        # 🔥 GROUP VULNERABILITIES
        # -------------------------
        categorized = {
            "authentication": [],
            "headers": [],
            "transport": [],
            "content": [],
            "other": []
        }

        for item in findings:
            issue = item.get("issue", "").lower()

            if "auth" in issue:
                categorized["authentication"].append(item)

            elif "header" in issue or "x-" in issue or "csp" in issue:
                categorized["headers"].append(item)

            elif "http" in issue or "ssl" in issue:
                categorized["transport"].append(item)

            elif "content" in issue or "body" in issue:
                categorized["content"].append(item)

            else:
                categorized["other"].append(item)

        # -------------------------
        # 🎯 FINAL CLEAN RESPONSE
        # -------------------------
        return {
            "success": True,
            "timestamp": datetime.utcnow().isoformat(),

            "analysis": {
                "risk_score": result.get("overall_risk_score", 0),
                "severity": result.get("severity", "LOW"),

                # ✅ NO raw findings here anymore
                "vulnerabilities": categorized,
                "total_issues": len(findings),

                "ai_suggestions": {
                    "issue": ai_data.get("issue", ""),
                    "summary": ai_data.get("summary", ""),
                    "fix": ai_data.get("fix", "")
                }
            }
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
