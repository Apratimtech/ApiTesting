import re
import json
import grpc
from typing import Dict, Any


# =========================================================
# CONFIG
# =========================================================

MAX_PAYLOAD_SIZE = 1024 * 1024  # 1MB

BLOCKED_HEADERS = [
    "x-forwarded-for",
    "x-real-ip",
    "cf-connecting-ip",
    "forwarded",
    "client-ip",
]

BLOCKED_PATTERNS = [
    r"<script.*?>.*?</script>",
    r"(union(\s)+select)",
    r"(drop(\s)+table)",
    r"(\.\./)",
    r"`.*?`",
    r"\$\(.*?\)",
]

REQUIRED_SECURITY_HEADERS = [
    "authorization",
]


# =========================================================
# PAYLOAD SIZE VALIDATION
# =========================================================

def validate_payload_size(
    payload: Dict[str, Any],
    context,
):

    payload_size = len(
        json.dumps(payload)
    )

    if payload_size > MAX_PAYLOAD_SIZE:

        context.abort(
            grpc.StatusCode.INVALID_ARGUMENT,
            (
                "Payload exceeds "
                "maximum allowed size"
            ),
        )


# =========================================================
# METADATA VALIDATION
# =========================================================

def validate_metadata(
    metadata,
    context,
):

    metadata_keys = []

    for key, value in metadata:

        normalized_key = key.lower()

        metadata_keys.append(
            normalized_key
        )

        # =============================================
        # BLOCKED HEADERS
        # =============================================

        if normalized_key in BLOCKED_HEADERS:

            context.abort(
                grpc.StatusCode.PERMISSION_DENIED,
                (
                    f"Blocked metadata detected: "
                    f"{key}"
                ),
            )

        # =============================================
        # HEADER LENGTH PROTECTION
        # =============================================

        if len(value) > 4096:

            context.abort(
                grpc.StatusCode.INVALID_ARGUMENT,
                (
                    f"Metadata value too large "
                    f"for key: {key}"
                ),
            )

    # =================================================
    # REQUIRED SECURITY HEADERS
    # =================================================

    for required in REQUIRED_SECURITY_HEADERS:

        if required not in metadata_keys:

            context.abort(
                grpc.StatusCode.UNAUTHENTICATED,
                (
                    f"Missing required "
                    f"security metadata: "
                    f"{required}"
                ),
            )


# =========================================================
# PAYLOAD CONTENT VALIDATION
# =========================================================

def validate_payload_content(
    payload: Dict[str, Any],
    context,
):

    payload_text = json.dumps(
        payload
    )

    for pattern in BLOCKED_PATTERNS:

        if re.search(
            pattern,
            payload_text,
            re.IGNORECASE,
        ):

            context.abort(
                grpc.StatusCode.PERMISSION_DENIED,
                (
                    "Malicious payload pattern "
                    "detected"
                ),
            )


# =========================================================
# FIELD VALIDATION
# =========================================================

def validate_required_fields(
    payload: Dict[str, Any],
    required_fields,
    context,
):

    missing_fields = []

    for field in required_fields:

        if field not in payload:

            missing_fields.append(
                field
            )

    if missing_fields:

        context.abort(
            grpc.StatusCode.INVALID_ARGUMENT,
            (
                "Missing required fields: "
                f"{', '.join(missing_fields)}"
            ),
        )


# =========================================================
# TYPE VALIDATION
# =========================================================

def validate_field_types(
    payload: Dict[str, Any],
    schema: Dict[str, type],
    context,
):

    for field, expected_type in schema.items():

        if field not in payload:
            continue

        if not isinstance(
            payload[field],
            expected_type,
        ):

            context.abort(
                grpc.StatusCode.INVALID_ARGUMENT,
                (
                    f"Invalid type for field "
                    f"'{field}'. "
                    f"Expected "
                    f"{expected_type.__name__}"
                ),
            )


# =========================================================
# RATE LIMIT VALIDATION
# =========================================================

def validate_request_rate(
    request_count: int,
    limit: int,
    context,
):

    if request_count > limit:

        context.abort(
            grpc.StatusCode.RESOURCE_EXHAUSTED,
            (
                "Rate limit exceeded"
            ),
        )


# =========================================================
# JWT FORMAT VALIDATION
# =========================================================

def validate_jwt_format(
    token: str,
    context,
):

    jwt_pattern = (
        r"^[A-Za-z0-9-_]+\."
        r"[A-Za-z0-9-_]+\."
        r"[A-Za-z0-9-_]+$"
    )

    if not re.match(
        jwt_pattern,
        token,
    ):

        context.abort(
            grpc.StatusCode.UNAUTHENTICATED,
            (
                "Invalid JWT format"
            ),
        )


# =========================================================
# IP VALIDATION
# =========================================================

def validate_ip_address(
    ip_address: str,
    blocked_ips,
    context,
):

    if ip_address in blocked_ips:

        context.abort(
            grpc.StatusCode.PERMISSION_DENIED,
            (
                "Blocked IP address"
            ),
        )


# =========================================================
# MAIN SECURITY VALIDATION PIPELINE
# =========================================================

def validate_request(
    payload: Dict[str, Any],
    metadata,
    context,
):

    validate_payload_size(
        payload,
        context,
    )

    validate_metadata(
        metadata,
        context,
    )

    validate_payload_content(
        payload,
        context,
    )
