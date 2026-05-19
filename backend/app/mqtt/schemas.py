# Enterprise-Level MQTT Models (Pydantic v2)

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
)


# =========================================================
# ENUMS
# =========================================================

class MQTTProtocol(str, Enum):
    MQTT = "mqtt"
    MQTTS = "mqtts"
    WS = "ws"
    WSS = "wss"


class MQTTLogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class MQTTMessageDirection(str, Enum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"


class MQTTSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# =========================================================
# BASE MODEL
# =========================================================

class MQTTBaseModel(BaseModel):
    """
    Common base model for all MQTT schemas.
    """

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        populate_by_name=True,
        use_enum_values=True,
        str_strip_whitespace=True,
    )


# =========================================================
# MQTT CONNECTION REQUEST
# =========================================================

class MQTTConnectRequest(MQTTBaseModel):
    broker_host: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="MQTT broker hostname or IP address",
        examples=["broker.emqx.io"],
    )

    broker_port: int = Field(
        default=1883,
        ge=1,
        le=65535,
        description="MQTT broker port",
    )

    protocol: MQTTProtocol = Field(
        default=MQTTProtocol.MQTT,
        description="MQTT transport protocol",
    )

    websocket_path: Optional[str] = Field(
        default="/mqtt",
        max_length=255,
        description="WebSocket path for WS/WSS protocols",
    )

    client_id: str = Field(
        ...,
        min_length=3,
        max_length=128,
        description="Unique MQTT client identifier",
    )

    username: Optional[str] = Field(
        default=None,
        max_length=255,
    )

    password: Optional[str] = Field(
        default=None,
        max_length=1024,
    )

    clean_session: bool = Field(
        default=True,
        description="Start a clean MQTT session",
    )

    keepalive: int = Field(
        default=60,
        ge=10,
        le=3600,
        description="Keepalive interval in seconds",
    )

    auto_reconnect: bool = Field(
        default=True,
        description="Enable automatic reconnection",
    )

    reconnect_interval: int = Field(
        default=5,
        ge=1,
        le=300,
        description="Reconnect retry interval in seconds",
    )

    tls_enabled: bool = Field(
        default=False,
        description="Enable TLS/SSL encryption",
    )

    tls_insecure: bool = Field(
        default=False,
        description="Disable TLS certificate verification",
    )

    ca_cert_path: Optional[str] = Field(
        default=None,
        description="CA certificate path",
    )

    client_cert_path: Optional[str] = Field(
        default=None,
        description="Client certificate path",
    )

    client_key_path: Optional[str] = Field(
        default=None,
        description="Client private key path",
    )

    subscribe_topics: List[str] = Field(
        default_factory=lambda: ["#"],
        description="Topics to subscribe after connection",
    )

    qos: int = Field(
        default=0,
        ge=0,
        le=2,
        description="MQTT Quality of Service level",
    )

    session_expiry: int = Field(
        default=0,
        ge=0,
        le=86400,
        description="Session expiry interval in seconds",
    )

    receive_maximum: int = Field(
        default=100,
        ge=1,
        le=10000,
        description="Maximum simultaneous QoS messages",
    )

    maximum_packet_size: int = Field(
        default=1048576,
        ge=1024,
        le=268435455,
        description="Maximum MQTT packet size",
    )

    user_properties: Optional[Dict[str, str]] = Field(
        default=None,
        description="Custom MQTT v5 user properties",
    )

    @field_validator("subscribe_topics")
    @classmethod
    def validate_topics(cls, value: List[str]) -> List[str]:
        if not value:
            raise ValueError("At least one topic is required")

        for topic in value:
            if not topic.strip():
                raise ValueError("Topic cannot be empty")

        return value

    @field_validator("protocol")
    @classmethod
    def validate_protocol(cls, value: MQTTProtocol) -> MQTTProtocol:
        return value


# =========================================================
# MQTT PUBLISH REQUEST
# =========================================================

class MQTTPublishRequest(MQTTBaseModel):
    topic: str = Field(
        ...,
        min_length=1,
        max_length=65535,
        description="MQTT publish topic",
    )

    payload: Union[
        Dict[str, Any],
        List[Any],
        str,
        int,
        float,
        bool,
    ] = Field(
        ...,
        description="Message payload",
    )

    qos: int = Field(
        default=0,
        ge=0,
        le=2,
    )

    retain: bool = Field(
        default=False,
        description="Retain published message",
    )

    duplicate: bool = Field(
        default=False,
        description="Duplicate delivery flag",
    )

    content_type: Optional[str] = Field(
        default="application/json",
        max_length=255,
    )

    response_topic: Optional[str] = Field(
        default=None,
        max_length=65535,
    )

    correlation_data: Optional[str] = Field(
        default=None,
        max_length=1024,
    )

    message_expiry_interval: Optional[int] = Field(
        default=None,
        ge=1,
        le=86400,
    )

    properties: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Additional MQTT v5 properties",
    )


# =========================================================
# MQTT SUBSCRIBE REQUEST
# =========================================================

class MQTTSubscribeRequest(MQTTBaseModel):
    topics: List[str] = Field(
        ...,
        min_length=1,
        description="List of topics to subscribe",
    )

    qos: int = Field(
        default=0,
        ge=0,
        le=2,
    )

    no_local: bool = False

    retain_as_published: bool = False

    retain_handling: int = Field(
        default=0,
        ge=0,
        le=2,
    )


# =========================================================
# MQTT UNSUBSCRIBE REQUEST
# =========================================================

class MQTTUnsubscribeRequest(MQTTBaseModel):
    topics: List[str] = Field(
        ...,
        min_length=1,
        description="Topics to unsubscribe",
    )


# =========================================================
# MQTT DISCONNECT REQUEST
# =========================================================

class MQTTDisconnectRequest(MQTTBaseModel):
    reason: Optional[str] = Field(
        default="Client disconnect",
        max_length=255,
    )


# =========================================================
# MQTT MESSAGE MODEL
# =========================================================

class MQTTMessage(MQTTBaseModel):
    id: str = Field(
        ...,
        min_length=1,
        max_length=128,
    )

    topic: str = Field(
        ...,
        min_length=1,
        max_length=65535,
    )

    payload: Any

    qos: int = Field(
        ...,
        ge=0,
        le=2,
    )

    retain: bool

    duplicate: bool

    timestamp: datetime

    direction: MQTTMessageDirection

    broker: str = Field(
        ...,
        min_length=1,
        max_length=255,
    )

    client_id: str = Field(
        ...,
        min_length=1,
        max_length=128,
    )

    size_bytes: int = Field(
        ...,
        ge=0,
    )

    content_type: Optional[str] = Field(
        default=None,
        max_length=255,
    )


# =========================================================
# MQTT LIVE LOG MODEL
# =========================================================

class MQTTLog(MQTTBaseModel):
    timestamp: datetime

    level: MQTTLogLevel

    event: str = Field(
        ...,
        min_length=1,
        max_length=255,
    )

    message: str = Field(
        ...,
        min_length=1,
        max_length=5000,
    )

    metadata: Optional[Dict[str, Any]] = None


# =========================================================
# MQTT CONNECTION STATUS
# =========================================================

class MQTTConnectionStatus(MQTTBaseModel):
    connected: bool

    broker: Optional[str] = None

    protocol: Optional[MQTTProtocol] = None

    client_id: Optional[str] = None

    subscribed_topics: List[str] = Field(
        default_factory=list,
    )

    uptime_seconds: Optional[int] = Field(
        default=None,
        ge=0,
    )

    packets_sent: int = Field(
        default=0,
        ge=0,
    )

    packets_received: int = Field(
        default=0,
        ge=0,
    )

    reconnect_count: int = Field(
        default=0,
        ge=0,
    )

    tls_enabled: bool = False

    last_ping: Optional[datetime] = None


# =========================================================
# MQTT SECURITY FINDING
# =========================================================

class MQTTSecurityFinding(MQTTBaseModel):
    severity: MQTTSeverity

    title: str = Field(
        ...,
        min_length=1,
        max_length=255,
    )

    description: str = Field(
        ...,
        min_length=1,
        max_length=5000,
    )

    recommendation: str = Field(
        ...,
        min_length=1,
        max_length=5000,
    )

    cve: Optional[str] = Field(
        default=None,
        max_length=50,
    )


# =========================================================
# MQTT ANALYSIS RESPONSE
# =========================================================

class MQTTAnalysisResponse(MQTTBaseModel):
    broker: str = Field(
        ...,
        min_length=1,
        max_length=255,
    )

    findings: List[MQTTSecurityFinding] = Field(
        default_factory=list,
    )

    security_score: int = Field(
        ...,
        ge=0,
        le=100,
        description="Security score from 0 to 100",
    )

    tls_enabled: bool

    anonymous_access: bool

    wildcard_subscription_detected: bool

    retained_messages_detected: bool


# =========================================================
# OPTIONAL STANDARD API RESPONSE MODEL
# =========================================================

class MQTTAPIResponse(MQTTBaseModel):
    success: bool = True

    message: str = Field(
        ...,
        min_length=1,
        max_length=500,
    )

    data: Optional[Any] = None

    timestamp: datetime = Field(
        default_factory=datetime.utcnow,
    )

