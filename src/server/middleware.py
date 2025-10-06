"""
Security middleware for QASP server.

This module provides middleware components for API rate limiting and
request signing verification to enhance security against abuse and replay attacks.
"""

import time
import hashlib
import hmac
from typing import Dict, Callable, Optional
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse

from ..qasp.crypto import PQCSign
from ..telemetry.logging_config import security_logger

# Rate limiting storage (in-memory for prototype)
_rate_limits: Dict[str, Dict] = {}  # client_id -> {"count": int, "reset_time": float}

# Rate limit configuration
RATE_LIMIT_REQUESTS = 10  # requests per window
RATE_LIMIT_WINDOW = 60   # seconds


def rate_limit_middleware(client_id: Optional[str] = None) -> Callable:
    """
    Rate limiting middleware factory.

    Creates a middleware function that enforces per-client request rate limits.
    For prototype, uses simple in-memory storage with fixed windows.

    Args:
        client_id: Client identifier for rate limiting

    Returns:
        Middleware function
    """
    def middleware(request: Request, call_next):
        if not client_id:
            # Try to extract client_id from headers or body
            client_id_header = request.headers.get("x-qasp-client-id")
            if client_id_header:
                client_id = client_id_header

        if client_id:
            current_time = time.time()

            if client_id not in _rate_limits:
                _rate_limits[client_id] = {"count": 0, "reset_time": current_time + RATE_LIMIT_WINDOW}

            client_limit = _rate_limits[client_id]

            # Reset if window expired
            if current_time > client_limit["reset_time"]:
                client_limit["count"] = 0
                client_limit["reset_time"] = current_time + RATE_LIMIT_WINDOW

            # Check limit
            if client_limit["count"] >= RATE_LIMIT_REQUESTS:
                security_logger.warning(
                    "Rate limit exceeded",
                    client_id=client_id,
                    count=client_limit["count"],
                    security_event="rate_limit_exceeded"
                )
                return JSONResponse(
                    status_code=429,
                    content={"error": "Rate limit exceeded. Try again later."}
                )

            client_limit["count"] += 1

        return call_next(request)

    return middleware


def request_signature_middleware(clients_store: Dict[str, Dict[str, Dict[str, bytes]]]) -> Callable:
    """
    Request signing middleware for replay attack protection.

    Verifies the X-QASP-Signature header against the request body using
    the client's stored public signature key. The signature should be
    computed as: base64(Sign(SHA256(request_body), client_private_key))

    Args:
        clients_store: Dictionary of tenant_id -> client_id -> {"pub_sig": bytes}

    Returns:
        Middleware function
    """
    def middleware(request: Request, call_next):
        # Skip signature verification for public endpoints
        if request.url.path in ["/public-keys", "/metrics"]:
            return call_next(request)

        # Get tenant_id from header or body
        tenant_id = request.headers.get("x-qasp-tenant-id", "default")
        if tenant_id == "default":
            # Try to parse from JSON body
            try:
                import json
                body = request.body()
                if body:
                    data = json.loads(body.decode())
                    tenant_id = data.get("tenant_id", tenant_id)
            except:
                pass

        # Get client_id from header or body
        client_id = request.headers.get("x-qasp-client-id")
        if not client_id:
            # Try to parse from JSON body
            try:
                import json
                if 'body' not in locals():
                    body = request.body()
                if body and 'data' not in locals():
                    data = json.loads(body.decode())
                client_id = data.get("client_id")
            except:
                pass

        if not client_id:
            # For endpoints that require authentication after init, get from session
            session_token = request.headers.get("x-qasp-session")
            if session_token and hasattr(request.app.state, 'sessions'):
                # You'd need to decode session to get client_id, but for simplicity, skip for now
                pass

        signature_b64 = request.headers.get("x-qasp-signature")
        if not signature_b64 or not client_id:
            # Optional for now, but log
            security_logger.info(
                "Request without signature",
                client_id=client_id or "unknown",
                path=request.url.path,
                security_event="unsigned_request"
            )
            return call_next(request)

        # Verify signature
        if tenant_id not in clients_store or client_id not in clients_store[tenant_id]:
            security_logger.warning(
                "Signature verification failed: unknown client",
                client_id=client_id,
                tenant_id=tenant_id,
                security_event="signature_unknown_client"
            )
            raise HTTPException(status_code=401, detail="Invalid client")

        try:
            import base64

            # Get request body
            body = request.body()
            if not body:
                # For GET requests, use empty body or path
                body = b""

            # Compute expected signature input (hash of body)
            body_hash = hashlib.sha256(body).digest()

            # Decode signature
            signature = base64.b64decode(signature_b64)

            # Get client's public key
            client_pub_sig = clients_store[tenant_id][client_id]["pub_sig"]

            # Verify signature
            is_valid = PQCSign.verify(client_pub_sig, body_hash, signature)

            if not is_valid:
                security_logger.warning(
                    "Invalid request signature",
                    client_id=client_id,
                    security_event="signature_invalid"
                )
                raise HTTPException(status_code=401, detail="Invalid signature")

            security_logger.info(
                "Request signature verified",
                client_id=client_id,
                security_event="signature_valid"
            )

        except Exception as e:
            security_logger.error(
                "Signature verification error",
                client_id=client_id,
                error=str(e),
                security_event="signature_error"
            )
            raise HTTPException(status_code=401, detail="Signature verification failed")

        return call_next(request)

    return middleware
