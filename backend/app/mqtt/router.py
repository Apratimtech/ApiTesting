# app/mqtt/router.py
from datetime import datetime
from fastapi import (
    APIRouter,
    HTTPException,
    status,
)

# =========================================================
# MQTT IMPORTS
# =========================================================
from app.mqtt.schemas import (
    MQTTConnectRequest,
    MQTTPublishRequest,
    MQTTSubscribeRequest,
    MQTTDisconnectRequest,
)
from app.mqtt.client import (
    MQTTClientManager,
)
from app.mqtt.analysis import analyze_request

# =========================================================
# STORAGE IMPORTS
# =========================================================
from app.db.postgres import SessionLocal
from app.services.analyzer_storage import analyzer_storage

# =========================================================
# ROUTER
# =========================================================
router = APIRouter(
    prefix="/mqtt",
    tags=["MQTT"],
)

mqtt_manager = MQTTClientManager()


# =========================================================
# CONNECT
# =========================================================
@router.post("/connect")
async def connect_mqtt(
    data: MQTTConnectRequest,
):
    try:
        result = await mqtt_manager.connect(
            broker_host=data.broker_host,
            broker_port=data.broker_port,
            username=data.username,
            password=data.password,
            client_id=data.client_id,
            tls_enabled=data.tls_enabled,
            tls_insecure=data.tls_insecure,
            keepalive=data.keepalive,
        )

        if not result.get("success"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.get("message", "MQTT connection failed"),
            )

        for topic in data.subscribe_topics:
            await mqtt_manager.subscribe(
                topic=topic,
                qos=data.qos,
            )

        # Security Analysis
        analysis = analyze_request(
            "connect",
            data.model_dump()
        )

        return {
            "success": True,
            "message": "MQTT connected successfully",
            "broker": data.broker_host,
            "port": data.broker_port,
            "client_id": result.get("client_id"),
            "subscriptions": data.subscribe_topics,
            "riskScore": analysis["riskScore"],
            "latency": analysis["latency"],
            "securityFindings": analysis["securityFindings"],
            "timestamp": datetime.utcnow().isoformat(),
        }

    except HTTPException:
        raise
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )


# =========================================================
# PUBLISH
# =========================================================
@router.post("/publish")
async def publish_mqtt(
    data: MQTTPublishRequest,
):
    try:
        result = await mqtt_manager.publish(
            topic=data.topic,
            payload=data.payload,
            qos=data.qos,
            retain=data.retain,
        )

        if not result.get("success"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.get("message", "Publish failed"),
            )

        # Security Analysis
        analysis = analyze_request(
            "publish",
            data.model_dump()
        )

        # ==================== DEBUG PRINT ====================
        print("=" * 80)
        print("MQTT ANALYSIS")
        print(analysis)
        print("=" * 80)
        # ====================================================

        # Save analysis
        db = SessionLocal()
        try:
            status_data = mqtt_manager.get_status()
            broker_url = (
                status_data.get("broker_host")
                or status_data.get("broker")
                or "mqtt-broker"
            )

            analyzer_storage.save_analysis(
                db=db,
                request_data={
                    "protocol": "MQTT",
                    "url": broker_url,
                    "method": "PUBLISH",
                    "protocol_metadata": {
                        "topic": data.topic,
                        "qos": data.qos,
                    },
                },
                response_data={
                    "status": 200,
                    "headers": {},
                    "body": {"published": True},
                },
                analysis_result={
                    "success": analysis["success"],
                    "severity": (
                        "CRITICAL" if analysis["riskScore"] >= 80
                        else "HIGH" if analysis["riskScore"] >= 60
                        else "MEDIUM" if analysis["riskScore"] >= 30
                        else "LOW"
                    ),
                    "overall_risk_score": analysis["riskScore"],
                    "securityFindings": analysis["securityFindings"],
                    "summary": analysis["message"],
                },
            )
        finally:
            db.close()

        return {
            "success": True,
            "message": "Message published successfully",
            "topic": data.topic,
            "qos": data.qos,
            "retain": data.retain,
            "message_id": result.get("message_id"),
            "riskScore": analysis["riskScore"],
            "latency": analysis["latency"],
            "securityFindings": analysis["securityFindings"],
            "timestamp": datetime.utcnow().isoformat(),
        }

    except HTTPException:
        raise
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )


# =========================================================
# SUBSCRIBE
# =========================================================
@router.post("/subscribe")
async def subscribe_mqtt(
    data: MQTTSubscribeRequest,
):
    try:
        # Security Analysis
        analysis = analyze_request(
            "subscribe",
            data.model_dump()
        )

        subscribed_topics = []
        for topic in data.topics:
            await mqtt_manager.subscribe(
                topic=topic,
                qos=data.qos,
            )
            subscribed_topics.append(topic)

        return {
            "success": True,
            "message": "Subscribed successfully",
            "topics": subscribed_topics,
            "qos": data.qos,
            "riskScore": analysis["riskScore"],
            "securityFindings": analysis["securityFindings"],
            "timestamp": datetime.utcnow().isoformat(),
        }

    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )


# =========================================================
# UNSUBSCRIBE
# =========================================================
@router.post("/unsubscribe")
async def unsubscribe_mqtt(
    data: MQTTSubscribeRequest,
):
    try:
        unsubscribed_topics = []
        for topic in data.topics:
            await mqtt_manager.unsubscribe(topic=topic)
            unsubscribed_topics.append(topic)

        return {
            "success": True,
            "message": "Unsubscribed successfully",
            "topics": unsubscribed_topics,
            "timestamp": datetime.utcnow().isoformat(),
        }

    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )


# =========================================================
# STATUS
# =========================================================
@router.get("/status")
async def mqtt_status():
    try:
        return {
            "success": True,
            "data": mqtt_manager.get_status(),
            "timestamp": datetime.utcnow().isoformat(),
        }
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )


# =========================================================
# GET MESSAGES
# =========================================================
@router.get("/messages")
async def get_messages():
    try:
        messages = mqtt_manager.get_messages()
        return {
            "success": True,
            "count": len(messages),
            "messages": messages,
            "timestamp": datetime.utcnow().isoformat(),
        }
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )


# =========================================================
# GET LOGS
# =========================================================
@router.get("/logs")
async def get_logs():
    try:
        logs = mqtt_manager.get_logs()
        return {
            "success": True,
            "count": len(logs),
            "logs": logs,
            "timestamp": datetime.utcnow().isoformat(),
        }
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )


# =========================================================
# DISCONNECT
# =========================================================
@router.post("/disconnect")
async def disconnect_mqtt(
    data: MQTTDisconnectRequest | None = None,
):
    try:
        result = await mqtt_manager.disconnect()

        if not result.get("success"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.get("message", "Disconnect failed"),
            )

        return {
            "success": True,
            "message": data.reason if data else "MQTT disconnected",
            "timestamp": datetime.utcnow().isoformat(),
        }

    except HTTPException:
        raise
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )
