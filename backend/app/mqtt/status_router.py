# app/mqtt/status_router.py

from fastapi import APIRouter, Query

from app.mqtt.session_manager import mqtt_session

router = APIRouter(
    prefix="/mqtt",
    tags=["MQTT Status"],
)


# =====================================================
# STATUS
# =====================================================

@router.get("/status")
async def mqtt_status():
    """
    Get MQTT connection status and statistics.
    """

    status = mqtt_session.get_status()

    return {
        "success": status["connected"],
        "data": status,
    }


# =====================================================
# MESSAGES
# =====================================================

@router.get("/messages")
async def mqtt_messages(
    limit: int = Query(
        default=20,
        ge=1,
        le=500,
        description="Number of messages to return",
    )
):
    """
    Get recent MQTT messages.
    """

    return {
        "success": True,
        "count": min(limit, len(mqtt_session.messages)),
        "messages": mqtt_session.get_messages(limit),
    }


# =====================================================
# CLEAR MESSAGES
# =====================================================

@router.delete("/messages")
async def clear_messages():
    """
    Clear stored MQTT messages.
    """

    before = len(mqtt_session.messages)

    mqtt_session.clear_messages()

    return {
        "success": True,
        "cleared_messages": before,
    }


# =====================================================
# SUBSCRIPTIONS
# =====================================================

@router.get("/subscriptions")
async def subscriptions():
    """
    Get subscribed topics.
    """

    topics = mqtt_session.get_subscriptions()

    return {
        "success": True,
        "count": len(topics),
        "subscriptions": topics,
    }


# =====================================================
# RESET SESSION
# =====================================================

@router.post("/reset")
async def reset_session():
    """
    Reset MQTT session state.
    """

    mqtt_session.reset()

    return {
        "success": True,
        "message": "MQTT session reset successfully",
    }
