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

        return {
            "success": result["success"],
            "message": result["message"],
            "client_id": result.get("client_id"),
        }

    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=str(e),
        )


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
