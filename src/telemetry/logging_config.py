"""
Structured logging configuration using structlog.

This module configures JSON-formatted logging with security tags, timestamps,
and structured data for better observability and audit trails.
"""

import logging
import structlog
import uuid
import datetime
from typing import Any, Dict


def configure_structured_logging():
    """
    Configure structlog for JSON logging with security context.

    Sets up processors to add timestamps, security event IDs, and format
    logs as JSON for easier parsing and analysis.
    """
    # Configure standard logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        handlers=[
            logging.StreamHandler()
        ]
    )

    # Configure structlog processors
    structlog.configure(
        processors=[
            # Add timestamp
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            add_timestamp,
            add_security_event_id,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            # Output as JSON
            JSONRenderer()
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )


def add_timestamp(logger, method_name: str, event_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Add ISO 8601 timestamp to log event."""
    event_dict["timestamp"] = datetime.datetime.utcnow().isoformat() + "Z"
    return event_dict


def add_security_event_id(logger, method_name: str, event_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Add security event ID for audit trails."""
    if "security_event" in str(event_dict.get("event", "")) or method_name in ["security", "error"]:
        event_dict["security_event_id"] = str(uuid.uuid4())
    return event_dict


class JSONRenderer(structlog.processors.JSONRenderer):
    """
    Custom JSON renderer that ensures proper formatting for security logs.

    Extends the base JSONRenderer to add additional processing if needed.
    """
    def __call__(self, logger, method_name, event_dict):
        # Ensure level is string
        if "level" in event_dict:
            event_dict["level"] = event_dict["level"].upper()

        return super().__call__(logger, method_name, event_dict)


# Convenience logger for security events
security_logger = structlog.get_logger("qasp.security")
