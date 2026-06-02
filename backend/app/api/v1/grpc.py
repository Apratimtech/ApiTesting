# grpc.py - ENTERPRISE DYNAMIC gRPC ENGINE

from fastapi import APIRouter, Body
from pydantic import BaseModel, Field
from typing import Dict, Any, Optional, List

from grpc.aio import insecure_channel, secure_channel

from google.protobuf.json_format import (
    MessageToDict,
    ParseDict
)

import grpc
import asyncio
import logging
import uuid
import time
import importlib


# =========================================================
# LOGGER
# =========================================================

logger = logging.getLogger("trust_edge.grpc")


# =========================================================
# ROUTER
# =========================================================

router = APIRouter(
    prefix="/grpc",
    tags=["Enterprise gRPC"]
)


# =========================================================
# REQUEST MODELS
# =========================================================

class GrpcMetadata(BaseModel):

    key: str

    value: str


class DynamicGrpcRequest(BaseModel):

    serverUrl: str = Field(
        ...,
        description="grpc://localhost:50051"
    )

    serviceName: str = Field(
        ...,
        description="user.UserService"
    )

    methodName: str = Field(
        ...,
        description="CreateUser"
    )

    metadata: Optional[List[GrpcMetadata]] = []

    payload: Dict[str, Any] = {}

    secure: Optional[bool] = False


class DynamicGrpcResponse(BaseModel):

    success: bool

    protocol: str = "gRPC"

    serverUrl: str

    serviceName: str

    methodName: str

    request_id: str

    latency_ms: float

    response: Optional[Dict[str, Any]] = None

    error: Optional[str] = None

    grpc_status_code: Optional[str] = None


# =========================================================
# CHANNEL MANAGER
# =========================================================

class GrpcChannelManager:

    def __init__(self):

        self.channels = {}

    async def get_channel(
        self,
        target: str,
        secure: bool = False
    ):

        if target in self.channels:

            return self.channels[target]

        parsed_target = target.replace(
            "grpc://",
            ""
        )

        options = [

            (
                "grpc.keepalive_time_ms",
                30000
            ),

            (
                "grpc.keepalive_timeout_ms",
                10000
            ),

            (
                "grpc.keepalive_permit_without_calls",
                True
            ),

            (
                "grpc.http2.max_pings_without_data",
                0
            ),

            (
                "grpc.max_receive_message_length",
                50 * 1024 * 1024
            ),

            (
                "grpc.max_send_message_length",
                50 * 1024 * 1024
            ),
        ]

        if secure:

            credentials = grpc.ssl_channel_credentials()

            channel = secure_channel(
                parsed_target,
                credentials,
                options=options
            )

        else:

            channel = insecure_channel(
                parsed_target,
                options=options
            )

        self.channels[target] = channel

        logger.info(
            f"✅ gRPC channel created: {parsed_target}"
        )

        return channel

    async def close_all(self):

        for channel in self.channels.values():

            try:

                await channel.close()

            except Exception:
                pass

        logger.info(
            "✅ All gRPC channels closed"
        )


channel_manager = GrpcChannelManager()


# =========================================================
# PROTOBUF UTILITIES
# =========================================================

def protobuf_to_dict(message):

    try:

        return MessageToDict(
            message,
            preserving_proto_field_name=True
        )

    except Exception:

        return {
            "raw": str(message)
        }


# =========================================================
# DYNAMIC MODULE LOADER
# =========================================================

def load_dynamic_stub(
    service_name: str
):

    try:

        service_parts = service_name.split(".")

        if len(service_parts) != 2:

            raise ValueError(
                "serviceName must be like user.UserService"
            )

        proto_name = service_parts[0]

        service_class_name = service_parts[1]

        pb2_module = importlib.import_module(
            f"app.grpc_proto.{proto_name}_pb2"
        )

        pb2_grpc_module = importlib.import_module(
            f"app.grpc_proto.{proto_name}_pb2_grpc"
        )

        stub_class = getattr(
            pb2_grpc_module,
            f"{service_class_name}Stub"
        )

        return pb2_module, stub_class

    except Exception as e:

        raise Exception(
            f"Failed loading stub: {str(e)}"
        )


# =========================================================
# CREATE REQUEST MESSAGE
# =========================================================

def create_request_message(
    pb2_module,
    method_name: str,
    payload: Dict[str, Any]
):

    request_class_name = (
        f"{method_name}Request"
    )

    request_class = getattr(
        pb2_module,
        request_class_name,
        None
    )

    if not request_class:

        raise Exception(
            f"Request class not found: "
            f"{request_class_name}"
        )

    message = request_class()

    ParseDict(
        payload,
        message
    )

    return message


# =========================================================
# MAIN gRPC INVOKER
# =========================================================

async def invoke_grpc_method(
    data: DynamicGrpcRequest
):

    request_id = str(uuid.uuid4())

    start_time = time.perf_counter()

    try:

        logger.info(
            f"[gRPC] "
            f"{data.serviceName}.{data.methodName}"
        )

        # =================================================
        # CHANNEL
        # =================================================

        channel = await channel_manager.get_channel(
            target=data.serverUrl,
            secure=data.secure
        )

        # =================================================
        # LOAD STUB
        # =================================================

        pb2_module, stub_class = load_dynamic_stub(
            data.serviceName
        )

        stub = stub_class(channel)

        # =================================================
        # CREATE REQUEST
        # =================================================

        request_message = create_request_message(
            pb2_module,
            data.methodName,
            data.payload
        )

        # =================================================
        # METHOD LOOKUP
        # =================================================

        grpc_method = getattr(
            stub,
            data.methodName,
            None
        )

        if not grpc_method:

            raise Exception(
                f"Method not found: "
                f"{data.methodName}"
            )

        # =================================================
        # METADATA
        # =================================================

        grpc_metadata = []

        for item in data.metadata:

            if item.key.strip():

                grpc_metadata.append(
                    (
                        item.key,
                        item.value
                    )
                )

        # =================================================
        # INVOKE RPC
        # =================================================

        response = await asyncio.wait_for(

            grpc_method(
                request_message,
                metadata=grpc_metadata,
                timeout=30
            ),

            timeout=35
        )

        latency_ms = (
            time.perf_counter() - start_time
        ) * 1000

        response_dict = protobuf_to_dict(
            response
        )

        logger.info(
            f"[gRPC SUCCESS] "
            f"{data.methodName} "
            f"{round(latency_ms, 2)}ms"
        )

        return DynamicGrpcResponse(

            success=True,

            serverUrl=data.serverUrl,

            serviceName=data.serviceName,

            methodName=data.methodName,

            request_id=request_id,

            latency_ms=round(
                latency_ms,
                2
            ),

            response=response_dict,

            grpc_status_code="OK"
        )

    except grpc.aio.AioRpcError as e:

        latency_ms = (
            time.perf_counter() - start_time
        ) * 1000

        logger.error(
            f"[gRPC ERROR] "
            f"{e.code().name}: "
            f"{e.details()}"
        )

        return DynamicGrpcResponse(

            success=False,

            serverUrl=data.serverUrl,

            serviceName=data.serviceName,

            methodName=data.methodName,

            request_id=request_id,

            latency_ms=round(
                latency_ms,
                2
            ),

            error=e.details(),

            grpc_status_code=e.code().name
        )

    except Exception as e:

        latency_ms = (
            time.perf_counter() - start_time
        ) * 1000

        logger.exception(
            "gRPC invoke failed"
        )

        return DynamicGrpcResponse(

            success=False,

            serverUrl=data.serverUrl,

            serviceName=data.serviceName,

            methodName=data.methodName,

            request_id=request_id,

            latency_ms=round(
                latency_ms,
                2
            ),

            error=str(e),

            grpc_status_code="INTERNAL"
        )


# =========================================================
# MAIN ENDPOINT
# =========================================================

@router.post(
    "/invoke",
    response_model=DynamicGrpcResponse
)
async def invoke_endpoint(

    data: DynamicGrpcRequest = Body(...)
):

    return await invoke_grpc_method(
        data
    )


# =========================================================
# HEALTH CHECK
# =========================================================

@router.get("/health")
async def grpc_health():

    return {

        "success": True,

        "service": "Enterprise gRPC Engine",

        "active_channels": len(
            channel_manager.channels
        ),

        "status": "healthy"
    }


# =========================================================
# CLEANUP
# =========================================================

@router.on_event("shutdown")
async def shutdown_grpc():

    await channel_manager.close_all()

    logger.info(
        "✅ gRPC shutdown complete"
    )
