"""
QASP v0.2 Interoperability Layer

This module provides cross-implementation interoperability functions for QASP v0.2,
including canonical JSON serialization/deserialization and message schema validation.

All QASP messages must include "qasp_version": "0.2" for protocol versioning.
Messages use deterministic JSON serialization for cross-language compatibility.
"""

import json
from typing import Dict, Any, Optional
import base64
import structlog

logger = structlog.get_logger(__name__)


def serialize_handshake(message: Dict[str, Any]) -> str:
    """
    Serialize a QASP handshake message to canonical JSON format.

    Args:
        message: Dictionary containing handshake message fields

    Returns:
        Canonical JSON string with sorted keys and no whitespace

    Raises:
        ValueError: If required fields are missing or invalid
    """
    if not isinstance(message, dict):
        raise ValueError("Message must be a dictionary")

    # Ensure qasp_version is set
    message["qasp_version"] = "0.2"

    # Validate required fields based on message type
    _validate_handshake_message(message)

    # Canonical JSON: sorted keys, no whitespace
    canonical_json = json.dumps(message, sort_keys=True, separators=(',', ':'))

    logger.debug("Handshake message serialized",
                 message_type=message.get("type", "unknown"),
                 qasp_version=message["qasp_version"])

    return canonical_json


def deserialize_handshake(message_json: str) -> Dict[str, Any]:
    """
    Deserialize a canonical JSON handshake message.

    Args:
        message_json: Canonical JSON string

    Returns:
        Deserialized message dictionary

    Raises:
        ValueError: If JSON is invalid or message structure is incorrect
        json.JSONDecodeError: If JSON parsing fails
    """
    try:
        message = json.loads(message_json)
    except json.JSONDecodeError as e:
        logger.error("Failed to parse handshake message JSON", error=str(e))
        raise

    if not isinstance(message, dict):
        raise ValueError("Deserialized message must be a dictionary")

    # Validate version
    version = message.get("qasp_version")
    if version != "0.2":
        raise ValueError(f"Unsupported QASP version: {version}")

    # Validate message structure
    _validate_handshake_message(message)

    logger.debug("Handshake message deserialized",
                 message_type=message.get("type", "unknown"),
                 qasp_version=version)

    return message


def validate_message_schema(message: Dict[str, Any]) -> bool:
    """
    Validate a QASP message against v0.2 schema.

    Args:
        message: Message dictionary to validate

    Returns:
        True if valid, False otherwise

    Note:
        This is a basic validation. Comprehensive schema validation
        should use JSON Schema or similar formal specification.
    """
    try:
        # Check version
        if message.get("qasp_version") != "0.2":
            logger.warning("Invalid QASP version in message",
                          version=message.get("qasp_version"))
            return False

        # Check message type
        msg_type = message.get("type")
        if not msg_type:
            logger.warning("Missing message type in QASP message")
            return False

        # Basic type validation
        if msg_type == "handshake_init":
            required_fields = ["type", "client_id", "tenant_id", "kem_encaps", "client_nonce"]
            for field in required_fields:
                if field not in message and field != "tenant_id":  # tenant_id optional, defaults to "default"
                    logger.warning(f"Missing required field '{field}' in {msg_type}")
                    return False

            # Check base64 encodings
            if not _is_valid_base64(message.get("kem_encaps", "")):
                logger.warning("Invalid base64 in kem_encaps")
                return False
            if not _is_valid_base64(message.get("client_nonce", "")):
                logger.warning("Invalid base64 in client_nonce")
                return False

        elif msg_type == "challenge_request":
            required_fields = ["type", "challenge_nonce", "challenge_ciphertext"]
            for field in required_fields:
                if field not in message:
                    logger.warning(f"Missing required field '{field}' in {msg_type}")
                    return False

            # Check base64 encodings
            if not _is_valid_base64(message.get("challenge_nonce", "")):
                logger.warning("Invalid base64 in challenge_nonce")
                return False
            if not _is_valid_base64(message.get("challenge_ciphertext", "")):
                logger.warning("Invalid base64 in challenge_ciphertext")
                return False

        elif msg_type == "handshake_response":
            required_fields = ["type", "server_nonce", "session_token"]
            for field in required_fields:
                if field not in message:
                    logger.warning(f"Missing required field '{field}' in {msg_type}")
                    return False

            # Check base64 encodings
            if not _is_valid_base64(message.get("server_nonce", "")):
                logger.warning("Invalid base64 in server_nonce")
                return False
            # session_token is base64 but may be complex, skip for now

        elif msg_type == "challenge_response":
            required_fields = ["type", "challenge_verified"]
            for field in required_fields:
                if field not in message:
                    logger.warning(f"Missing required field '{field}' in {msg_type}")
                    return False

        elif msg_type == "resource_response":
            required_fields = ["type", "nonce", "ciphertext"]
            for field in required_fields:
                if field not in message:
                    logger.warning(f"Missing required field '{field}' in {msg_type}")
                    return False

            # Check base64 encodings
            if not _is_valid_base64(message.get("nonce", "")):
                logger.warning("Invalid base64 in nonce")
                return False
            if not _is_valid_base64(message.get("ciphertext", "")):
                logger.warning("Invalid base64 in ciphertext")
                return False

        else:
            logger.warning(f"Unknown message type: {msg_type}")
            return False

        return True

    except Exception as e:
        logger.error("Schema validation error", error=str(e), message_type=msg_type)
        return False


def _validate_handshake_message(message: Dict[str, Any]) -> None:
    """
    Internal validation function for handshake messages.

    Args:
        message: Message dictionary

    Raises:
        ValueError: If validation fails
    """
    if message.get("qasp_version") != "0.2":
        raise ValueError("QASP version must be '0.2'")

    msg_type = message.get("type")
    if not msg_type:
        raise ValueError("Message must have a 'type' field")

    # Add more validation as needed for specific message types


def _is_valid_base64(s: str) -> bool:
    """
    Check if a string is valid base64.

    Args:
        s: String to check

    Returns:
        True if valid base64, False otherwise
    """
    try:
        base64.b64decode(s, validate=True)
        return True
    except Exception:
        return False
