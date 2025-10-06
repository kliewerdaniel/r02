"""
QASP v0.2 Formal Verification Model

This module provides symbolic constants and trace logging functions for formal
verification of the QASP protocol. It exports handshake states and logging
primitives compatible with tools like TLA+ and ProVerif.

The trace log captures protocol events for offline formal analysis and
conformance verification.
"""

import json
import os
from typing import Dict, Any, List
from datetime import datetime
import structlog

logger = structlog.get_logger(__name__)

# Handshake states for formal modeling
STATES = {
    "INIT": "handshake_initialization",
    "CHALLENGE": "challenge_verification",
    "ESTABLISHED": "session_established"
}

# Protocol constants for formal verification
PROTOCOL_VERSION = "0.2"
MAX_MESSAGE_SIZE = 65536  # 64KB max message size
SESSION_EXPIRY_SECONDS = 600  # 10 minutes

# Supported algorithms (for specification compliance)
SUPPORTED_KEM_ALGORITHMS = [
    "Kyber512",
    "Kyber768",
    "Kyber1024"
]

SUPPORTED_SIGNATURE_ALGORITHMS = [
    "Dilithium2",
    "Dilithium3",
    "Dilithium5"
]

SUPPORTED_SYMMETRIC_ALGORITHMS = [
    "AES-GCM",
    "ChaCha20-Poly1305"
]

# Transition model for handshake states
HANDSHAKE_TRANSITIONS = {
    "INIT": ["CHALLENGE"],
    "CHALLENGE": ["ESTABLISHED", "INIT"],  # Can fail back to INIT
    "ESTABLISHED": ["INIT"]  # Session expiry or failure
}

TRACE_LOG_FILE = "logs/trace_log.json"


def write_trace_log(event_type: str, payload: Dict[str, Any]) -> None:
    """
    Write a protocol trace event to the trace log.

    Args:
        event_type: Type of event (e.g., "handshake_init", "challenge_request", "session_established")
        payload: Event-specific data including tenant_id, session_id, client_id, etc.

    The trace log is a JSON array of events, with each event containing:
    - timestamp: ISO format timestamp
    - event_type: String identifier
    - qasp_version: Protocol version
    - payload: Event data
    """
    try:
        # Ensure logs directory exists
        os.makedirs("logs", exist_ok=True)

        # Create trace entry
        trace_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event_type": event_type,
            "qasp_version": PROTOCOL_VERSION,
            "payload": payload
        }

        # Read existing log or create new one
        if os.path.exists(TRACE_LOG_FILE):
            try:
                with open(TRACE_LOG_FILE, 'r') as f:
                    trace_log = json.load(f)
                if not isinstance(trace_log, list):
                    trace_log = []
            except (json.JSONDecodeError, FileNotFoundError):
                trace_log = []
        else:
            trace_log = []

        # Append new entry
        trace_log.append(trace_entry)

        # Write back to file with atomic replace
        temp_file = TRACE_LOG_FILE + ".tmp"
        with open(temp_file, 'w') as f:
            json.dump(trace_log, f, indent=2, sort_keys=True)
        os.rename(temp_file, TRACE_LOG_FILE)

        logger.info("Trace log entry written",
                   event_type=event_type,
                   session_id=payload.get("session_id"),
                   tenant_id=payload.get("tenant_id"))

    except Exception as e:
        logger.error("Failed to write trace log",
                    event_type=event_type,
                    error=str(e))
        # Don't raise exception to avoid breaking protocol flow


def get_trace_log() -> List[Dict[str, Any]]:
    """
    Retrieve the current trace log.

    Returns:
        List of trace events, or empty list if log doesn't exist
    """
    try:
        if os.path.exists(TRACE_LOG_FILE):
            with open(TRACE_LOG_FILE, 'r') as f:
                return json.load(f)
        return []
    except Exception as e:
        logger.error("Failed to read trace log", error=str(e))
        return []


def clear_trace_log() -> None:
    """
    Clear the trace log (useful for testing).
    """
    try:
        if os.path.exists(TRACE_LOG_FILE):
            os.remove(TRACE_LOG_FILE)
        logger.info("Trace log cleared")
    except Exception as e:
        logger.error("Failed to clear trace log", error=str(e))


def validate_state_transition(current_state: str, next_state: str, event_type: str) -> bool:
    """
    Validate if a state transition is allowed according to the protocol model.

    Args:
        current_state: Current handshake state
        next_state: Proposed next state
        event_type: Event that triggered the transition

    Returns:
        True if transition is valid, False otherwise
    """
    if current_state not in HANDSHAKE_TRANSITIONS:
        logger.warning("Unknown current state", state=current_state)
        return False

    if next_state not in HANDSHAKE_TRANSITIONS[current_state]:
        logger.warning("Invalid state transition",
                      from_state=current_state,
                      to_state=next_state,
                      event=event_type)
        return False

    logger.debug("Valid state transition",
                from_state=current_state,
                to_state=next_state,
                event=event_type)
    return True


# Convenience functions for common trace events
def trace_handshake_init(session_id: str, tenant_id: str, client_id: str) -> None:
    """Trace handshake initialization event."""
    write_trace_log("handshake_init", {
        "session_id": session_id,
        "tenant_id": tenant_id,
        "client_id": client_id,
        "state": STATES["INIT"]
    })


def trace_challenge_request(session_id: str, tenant_id: str, client_id: str) -> None:
    """Trace challenge request event."""
    write_trace_log("challenge_request", {
        "session_id": session_id,
        "tenant_id": tenant_id,
        "client_id": client_id,
        "state": STATES["CHALLENGE"]
    })


def trace_session_established(session_id: str, tenant_id: str, client_id: str) -> None:
    """Trace session establishment event."""
    write_trace_log("session_established", {
        "session_id": session_id,
        "tenant_id": tenant_id,
        "client_id": client_id,
        "state": STATES["ESTABLISHED"]
    })


def trace_session_failure(session_id: str, tenant_id: str, client_id: str, error: str) -> None:
    """Trace session failure event."""
    write_trace_log("session_failure", {
        "session_id": session_id,
        "tenant_id": tenant_id,
        "client_id": client_id,
        "error": error,
        "state": STATES["INIT"]
    })
