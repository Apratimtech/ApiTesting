from fastapi import (
    APIRouter,
    HTTPException,
)
from app.schemas.mqtt import (
    MQTTConnectRequest,
    MQTTPublishRequest,
    MQTTSubscribeRequest,
    MQTTUnsubscribeRequest,
)
from app.services.mqtt_client import (
    MQTTClientManager,
)
from app.mqtt.analysis import analyze_request

router = APIRouter(
    prefix="/mqtt",
    tags=["MQTT"],
)
mqtt_manager = MQTTClientManager()
# =========================================================
# CONNECT
# =========================================================
@router.post("/connect")
async def connect_mqtt(data: MQTTConnectRequest):

    analysis = analyze_request(
        "connect",
        data.model_dump()
    )

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

    return {
        "success": result["success"],
        "message": result.get("message", ""),
        "client_id": result.get("client_id"),

        "riskScore": analysis["riskScore"],
        "latency": analysis["latency"],
        "securityFindings": analysis["securityFindings"],
    }
# =========================================================
# DISCONNECT
# =========================================================
@router.post("/disconnect")
async def disconnect_mqtt():
    try:
        result = await mqtt_manager.disconnect()
        return result
    except Exception as e:
        raise HTTPException(
            status_code=500,
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
        analysis = analyze_request(
            "publish",
            data.model_dump()
        )

        result = await mqtt_manager.publish(
            topic=data.topic,
            payload=data.payload,
            qos=data.qos,
            retain=data.retain,
        )
        return {
            "success": True,
            "message": "Message published",
            "data": result,

            "riskScore": analysis["riskScore"],
            "securityFindings": analysis["securityFindings"],
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
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
        analysis = analyze_request(
            "subscribe",
            data.model_dump()
        )

        results = []
        for topic in data.topics:
            result = await mqtt_manager.subscribe(
                topic=topic,
                qos=data.qos,
            )
            results.append(result)
        return {
            "success": True,
            "subscriptions": results,

            "riskScore": analysis["riskScore"],
            "securityFindings": analysis["securityFindings"],
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=str(e),
        )
# =========================================================
# UNSUBSCRIBE
# =========================================================
@router.post("/unsubscribe")
async def unsubscribe_mqtt(
    data: MQTTUnsubscribeRequest,
):
    try:
        results = []
        for topic in data.topics:
            result = await mqtt_manager.unsubscribe(
                topic=topic,
            )
            results.append(result)
        return {
            "success": True,
            "unsubscribed": results,
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
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
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=str(e),
        )
# =========================================================
# LIVE MESSAGES
# =========================================================
@router.get("/messages")
async def mqtt_messages():
    try:
        return {
            "success": True,
            "count": len(
                mqtt_manager.get_messages()
            ),
            "messages": mqtt_manager.get_messages(),
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=str(e),
        )
# =========================================================
# LIVE LOGS
# =========================================================
@router.get("/logs")
async def mqtt_logs():
    try:
        return {
            "success": True,
            "count": len(
                mqtt_manager.get_logs()
            ),
            "logs": mqtt_manager.get_logs(),
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=str(e),
        )
