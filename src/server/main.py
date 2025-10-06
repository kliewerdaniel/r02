import os
import time
import uuid
import base64
from typing import Dict, Optional
from fastapi import FastAPI, HTTPException, Request, Response
import httpx
from src.qasp.crypto import PQCKEM, PQCSign, derive_session_key, aead_encrypt, aead_decrypt
from src.telemetry.logging_config import configure_structured_logging
from src.telemetry.metrics import (
    HANDSHAKE_TOTAL, CHALLENGE_TOTAL, RESOURCE_ACCESS_TOTAL, KEY_OPERATIONS_TOTAL,
    Timer, HANDSHAKE_DURATION, get_metrics
)
from .middleware import rate_limit_middleware, request_signature_middleware
import structlog

# Check if HSM is enabled
HSM_ENABLED = os.getenv("HSM_ENABLED", "false").lower() == "true"

# Configure structured logging
configure_structured_logging()

# Get logger
logger = structlog.get_logger(__name__)

# Validate crypto configuration at startup
from src.config.crypto_config import validate_crypto_config
validate_crypto_config()
logger.info("Crypto configuration validated successfully")

app = FastAPI(title="QASP Server v0.1", version="0.1.0")

# Initialize HSM keystore if enabled
keystore = None
if HSM_ENABLED:
    from src.hsm.mock_hsm import MockHSM
    keystore = MockHSM()
    app.state.keystore = keystore

# Server's cryptographic keys
server_kem = PQCKEM(keystore, "server")
server_sign = PQCSign(keystore, "server")
server_kem.generate_keypair()
server_sign.generate_keypair()

# In-memory stores for prototype
_clients: Dict[str, Dict[str, bytes]] = {}  # client_id -> {"pub_kem": bytes, "pub_sig": bytes}
_sessions: Dict[str, Dict] = {}  # session_token -> {"session_id": str, "expiry": float, "key": bytes}

# QKD service URL
QKD_URL = os.getenv("QKD_URL", "http://localhost:8080")

# Session expiry (10 minutes)
SESSION_EXPIRY = 600  # seconds

# Add security middleware
app.middleware("http")(rate_limit_middleware())
app.middleware("http")(request_signature_middleware(_clients))

@app.get("/public-keys")
def get_public_keys():
    return {
        "pub_kem": base64.b64encode(server_kem.export_public()).decode(),
        "pub_sig": base64.b64encode(server_sign.export_public()).decode(),
    }

@app.post("/qasp/register")
async def register_client(client_id: str, request: Request):
    """
    Register a client with their public keys (simulate out-of-band).
    In production, add admin authentication.
    """
    data = await request.json()
    pub_kem_b64 = data.get("pub_kem")
    pub_sig_b64 = data.get("pub_sig")
    if not pub_kem_b64 or not pub_sig_b64:
        raise HTTPException(status_code=400, detail="Missing pub_kem or pub_sig")

    _clients[client_id] = {
        "pub_kem": base64.b64decode(pub_kem_b64),
        "pub_sig": base64.b64decode(pub_sig_b64),
    }
    return {"status": "registered"}

@app.post("/qasp/init")
async def initialize_session(request: Request):
    """
    Initialize QASP session with PQC KEM + optional QKD.
    Returns session token and server nonce.
    """
    with Timer(HANDSHAKE_DURATION, {'operation': 'init'}):
        try:
            data = await request.json()
            client_id = data.get("client_id")
            kem_encaps_b64 = data.get("kem_encaps")
            client_nonce_b64 = data.get("client_nonce")
            supported_qkd = data.get("supported_qkd", False)

            if not client_id or not kem_encaps_b64 or not client_nonce_b64:
                raise HTTPException(status_code=400, detail="Missing required fields")

            if client_id not in _clients:
                raise HTTPException(status_code=404, detail="Client not registered")

            kem_encaps = base64.b64decode(kem_encaps_b64)
            client_nonce = base64.b64decode(client_nonce_b64)

            # Decapsulate shared secret
            shared_secret = server_kem.decapsulate(kem_encaps)

            # Optional QKD
            qkd_key = None
            if supported_qkd:
                async with httpx.AsyncClient() as client:
                    resp = await client.get(f"{QKD_URL}/qkd/session")
                    resp.raise_for_status()
                    qkd_data = resp.json()
                    qkd_key = base64.b64decode(qkd_data["qkd_key"])

            # Generate server nonce
            server_nonce = os.urandom(16)

            # Derive session key
            session_key = derive_session_key(shared_secret, qkd_key, None, client_nonce, server_nonce)

            # Create session token (AEAD encrypted with session key)
            session_id = str(uuid.uuid4())
            token_payload = {
                "session_id": session_id,
                "expiry": time.time() + SESSION_EXPIRY
            }
            payload_bytes = str(token_payload).encode()  # Simplify, in real use JSON dumps
            token_nonce, token_ct = aead_encrypt(session_key, payload_bytes, b"session-token")

            session_token = base64.b64encode(token_nonce + token_ct).decode()

            # Store session
            _sessions[session_token] = {
                "session_id": session_id,
                "expiry": token_payload["expiry"],
                "key": session_key
            }

            # Log successful handshake
            logger.info(
                "QASP session initialized successfully",
                client_id=client_id,
                session_id=session_id,
                qkd_used=supported_qkd,
                security_event="handshake_success"
            )

            HANDSHAKE_TOTAL.labels(result='success').inc()
            return {
                "server_nonce": base64.b64encode(server_nonce).decode(),
                "session_token": session_token
            }
        except Exception as e:
            HANDSHAKE_TOTAL.labels(result='failure').inc()
            logger.error(
                "QASP session initialization failed",
                client_id=data.get("client_id") if 'data' in locals() else None,
                error=str(e),
                security_event="handshake_failure"
            )
            raise

@app.post("/qasp/challenge")
async def challenge_session(request: Request):
    """
    Verify session token possession via decrypted challenge.
    """
    session_token = request.headers.get("x-qasp-session")
    if not session_token or session_token not in _sessions:
        CHALLENGE_TOTAL.labels(result='failure').inc()
        logger.warning("Challenge attempted with invalid session token", security_event="challenge_unauthorized")
        raise HTTPException(status_code=401, detail="Invalid or missing session token")

    session = _sessions[session_token]
    if time.time() > session["expiry"]:
        del _sessions[session_token]
        CHALLENGE_TOTAL.labels(result='failure').inc()
        logger.warning("Challenge attempted with expired session", session_id=session["session_id"], security_event="challenge_expired")
        raise HTTPException(status_code=401, detail="Session expired")

    data = await request.json()
    challenge_nonce_b64 = data.get("challenge_nonce")
    challenge_ct_b64 = data.get("challenge_ciphertext")

    if not challenge_nonce_b64 or not challenge_ct_b64:
        CHALLENGE_TOTAL.labels(result='failure').inc()
        logger.warning("Challenge request missing data", session_id=session["session_id"], security_event="challenge_invalid")
        raise HTTPException(status_code=400, detail="Missing challenge data")

    try:
        nonce = base64.b64decode(challenge_nonce_b64)
        ct = base64.b64decode(challenge_ct_b64)
        challenge_bytes = aead_decrypt(session["key"], nonce, ct, b"challenge")
        challenge_text = challenge_bytes.decode()
        if challenge_text != "challenge-test":
            raise Exception("Invalid challenge")
        CHALLENGE_TOTAL.labels(result='success').inc()
        logger.info("Challenge verified successfully", session_id=session["session_id"], security_event="challenge_success")
        return {"challenge_verified": True}
    except Exception as e:
        CHALLENGE_TOTAL.labels(result='failure').inc()
        logger.error("Challenge verification failed", session_id=session["session_id"], error=str(e), security_event="challenge_failure")
        raise HTTPException(status_code=401, detail="Challenge verification failed")

@app.get("/protected/resource")
def get_protected_resource(request: Request):
    """
    Protected resource, returns AEAD-encrypted response using session key.
    """
    session_token = request.headers.get("x-qasp-session")
    if not session_token or session_token not in _sessions:
        RESOURCE_ACCESS_TOTAL.labels(result='failure').inc()
        logger.warning("Protected resource access attempted with invalid session", security_event="resource_unauthorized")
        raise HTTPException(status_code=401, detail="Invalid or missing session token")

    session = _sessions[session_token]
    if time.time() > session["expiry"]:
        del _sessions[session_token]
        RESOURCE_ACCESS_TOTAL.labels(result='failure').inc()
        logger.warning("Protected resource access attempted with expired session", session_id=session["session_id"], security_event="resource_expired")
        raise HTTPException(status_code=401, detail="Session expired")

    response_plaintext = b"Hello, protected world from QASP v0.1"
    nonce, ct = aead_encrypt(session["key"], response_plaintext, b"response")

    RESOURCE_ACCESS_TOTAL.labels(result='success').inc()
    logger.info("Protected resource accessed successfully", session_id=session["session_id"], security_event="resource_access")

    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ct).decode()
    }

@app.get("/admin/keys")
def list_keys(request: Request):
    """
    Admin endpoint to list all registered keys in the keystore.
    Requires admin mode; for prototype, returns all.
    """
    if not HSM_ENABLED or keystore is None:
        raise HTTPException(status_code=404, detail="HSM not enabled")

    keys = keystore.list_keys()
    KEY_OPERATIONS_TOTAL.labels(operation='list', result='success').inc()
    return {"keys": keys}

@app.get("/metrics")
def metrics_endpoint():
    """
    Prometheus metrics endpoint for monitoring.
    """
    return Response(content=get_metrics(), media_type="text/plain")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
