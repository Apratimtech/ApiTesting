import httpx
import base64
import time
from fastapi import APIRouter, HTTPException

from app.services.full_analyzer import TrustEdgeAnalyzer

router = APIRouter()
analyzer = TrustEdgeAnalyzer()


@router.post("/send-request")
async def send_request(data: dict):
    try:
        method = data.get("method", "GET")
        url = data.get("url")
        headers = data.get("headers", {})
        body = data.get("body", None)
        auth = data.get("auth", {})

        if not url:
            raise HTTPException(status_code=400, detail="URL is required")

        # -------------------------
        # 🔐 AUTH
        # -------------------------
        if auth.get("type") == "bearer":
            headers["Authorization"] = f"Bearer {auth.get('token')}"

        elif auth.get("type") == "api_key":
            headers[auth.get("key", "x-api-key")] = auth.get("value")

        elif auth.get("type") == "basic":
            user_pass = f"{auth.get('username')}:{auth.get('password')}"
            encoded = base64.b64encode(user_pass.encode()).decode()
            headers["Authorization"] = f"Basic {encoded}"

        # -------------------------
        # 🚀 SEND REQUEST
        # -------------------------
        start_time = time.time()

        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.request(
                method=method,
                url=url,
                headers=headers,
                json=body if isinstance(body, dict) else None,
                content=body if isinstance(body, str) else None
            )

        duration = round(time.time() - start_time, 3)

        request_data = {
            "method": method,
            "url": url,
            "headers": headers,
            "body": body
        }

        response_data = {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": response.text[:3000],
            "time": f"{duration}s"
        }

        # -------------------------
        # 🧠 ANALYZER
        # -------------------------
        result = analyzer.analyze_full_packet(request_data, response_data)

        ai_data = result.get("ai_suggestions")

        if isinstance(ai_data, list):
            ai_data = ai_data[0] if ai_data else {}
        if not isinstance(ai_data, dict):
            ai_data = {}

        # -------------------------
        # 🔥 FIX: findings → categorized vulnerabilities
        # -------------------------
        findings = result.get("findings", [])

        vulnerabilities = {
            "authentication": [],
            "headers": [],
            "transport": [],
            "content": [],
            "other": []
        }

        for f in findings:
            issue = f.get("issue", "").lower()

            if "auth" in issue:
                vulnerabilities["authentication"].append(f)

            elif "header" in issue or "csp" in issue or "frame" in issue:
                vulnerabilities["headers"].append(f)

            elif "http" in issue or "ssl" in issue:
                vulnerabilities["transport"].append(f)

            elif "body" in issue or "content" in issue:
                vulnerabilities["content"].append(f)

            else:
                vulnerabilities["other"].append(f)

        # -------------------------
        # 🎯 FINAL RESPONSE
        # -------------------------
        return {
            "success": True,

            # 🔵 INPUT
            "request": request_data,

            # 🟢 RESPONSE (CLEAN)
            "response": response_data,

            # 🔴 ANALYSIS (SEPARATE)
            "analysis": {
                "risk_score": result.get("overall_risk_score", 0),
                "severity": result.get("severity", "LOW"),
                "vulnerabilities": vulnerabilities,
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
