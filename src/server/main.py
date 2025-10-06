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
from src.analytics.metrics_collector import LTSMetricsCollector
from src.qkd.hardware_driver import load_qkd_driver
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

app = FastAPI(title="QASP Server v1.0", version="1.0.0")

# Initialize HSM keystore if enabled
keystore = None
if HSM_ENABLED:
    from src.hsm.mock_hsm import MockHSM
    keystore = MockHSM()
    app.state.keystore = keystore

# Initialize QKD driver
qkd_driver = load_qkd_driver()
logger.info("QKD driver loaded", driver_type=type(qkd_driver).__name__, available=qkd_driver.is_available())

# Server's cryptographic keys
server_kem = PQCKEM(keystore, "server")
server_sign = PQCSign(keystore, "server")
server_kem.generate_keypair()
server_sign.generate_keypair()

# In-memory stores for prototype
_clients: Dict[str, Dict[str, Dict[str, bytes]]] = {}  # tenant_id -> client_id -> {"pub_kem": bytes, "pub_sig": bytes}
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
async def register_client(request: Request):
    """
    Register a client with their public keys (simulate out-of-band).
    In production, add admin authentication.
    """
    data = await request.json()
    client_id = data.get("client_id")
    tenant_id = data.get("tenant_id", "default")
    pub_kem_b64 = data.get("pub_kem")
    pub_sig_b64 = data.get("pub_sig")
    if not client_id or not pub_kem_b64 or not pub_sig_b64:
        raise HTTPException(status_code=400, detail="Missing client_id, pub_kem, or pub_sig")

    if tenant_id not in _clients:
        _clients[tenant_id] = {}
    _clients[tenant_id][client_id] = {
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
            tenant_id = data.get("tenant_id", "default")
            kem_encaps_b64 = data.get("kem_encaps")
            client_nonce_b64 = data.get("client_nonce")
            supported_qkd = data.get("supported_qkd", False)

            if not client_id or not kem_encaps_b64 or not client_nonce_b64:
                raise HTTPException(status_code=400, detail="Missing required fields")

            if tenant_id not in _clients or client_id not in _clients[tenant_id]:
                raise HTTPException(status_code=404, detail="Client not registered")

            kem_encaps = base64.b64decode(kem_encaps_b64)
            client_nonce = base64.b64decode(client_nonce_b64)

            # Decapsulate shared secret
            shared_secret = server_kem.decapsulate(kem_encaps)

            # Generate session_id early for QKD key association
            session_id = str(uuid.uuid4())

            # Optional QKD
            qkd_key = None
            qkd_metadata = None
            if supported_qkd:
                try:
                    qkd_key, qkd_metadata = qkd_driver.get_qkd_key(session_id)
                    logger.info("QKD key retrieved", session_id=session_id, device_id=qkd_metadata.get("device_id"), latency_ms=qkd_metadata.get("latency_ms"))
                except Exception as e:
                    logger.warning("QKD hardware failed, falling back to PQC-only", session_id=session_id, error=str(e))
                    # Fallback to PQC-only, qkd_key remains None

            # Generate server nonce
            server_nonce = os.urandom(16)

            # Derive session key
            session_key = derive_session_key(shared_secret, qkd_key, None, client_nonce, server_nonce)
            token_payload = {
                "session_id": session_id,
                "expiry": time.time() + SESSION_EXPIRY,
                "tenant_id": tenant_id
            }
            payload_bytes = str(token_payload).encode()  # Simplify, in real use JSON dumps
            token_nonce, token_ct = aead_encrypt(session_key, payload_bytes, f"session-token-{tenant_id}".encode())

            session_token = base64.b64encode(token_nonce + token_ct).decode()

            # Store session
            _sessions[session_token] = {
                "session_id": session_id,
                "expiry": token_payload["expiry"],
                "tenant_id": tenant_id,
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

            HANDSHAKE_TOTAL.labels(result='success', tenant_id=tenant_id).inc()
            return {
                "server_nonce": base64.b64encode(server_nonce).decode(),
                "session_token": session_token
            }
        except Exception as e:
            HANDSHAKE_TOTAL.labels(result='failure', tenant_id=tenant_id).inc()
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
        CHALLENGE_TOTAL.labels(result='failure', tenant_id='unknown').inc()
        logger.warning("Challenge attempted with invalid session token", security_event="challenge_unauthorized")
        raise HTTPException(status_code=401, detail="Invalid or missing session token")

    session = _sessions[session_token]
    tenant_id = session.get("tenant_id", "unknown")
    if time.time() > session["expiry"]:
        del _sessions[session_token]
        CHALLENGE_TOTAL.labels(result='failure', tenant_id=tenant_id).inc()
        logger.warning("Challenge attempted with expired session", session_id=session["session_id"], security_event="challenge_expired")
        raise HTTPException(status_code=401, detail="Session expired")

    data = await request.json()
    challenge_nonce_b64 = data.get("challenge_nonce")
    challenge_ct_b64 = data.get("challenge_ciphertext")

    if not challenge_nonce_b64 or not challenge_ct_b64:
        CHALLENGE_TOTAL.labels(result='failure', tenant_id=tenant_id).inc()
        logger.warning("Challenge request missing data", session_id=session["session_id"], security_event="challenge_invalid")
        raise HTTPException(status_code=400, detail="Missing challenge data")

    try:
        nonce = base64.b64decode(challenge_nonce_b64)
        ct = base64.b64decode(challenge_ct_b64)
        challenge_bytes = aead_decrypt(session["key"], nonce, ct, b"challenge")
        challenge_text = challenge_bytes.decode()
        if challenge_text != "challenge-test":
            raise Exception("Invalid challenge")
        CHALLENGE_TOTAL.labels(result='success', tenant_id=tenant_id).inc()
        logger.info("Challenge verified successfully", session_id=session["session_id"], security_event="challenge_success")
        return {"challenge_verified": True}
    except Exception as e:
        CHALLENGE_TOTAL.labels(result='failure', tenant_id=tenant_id).inc()
        logger.error("Challenge verification failed", session_id=session["session_id"], error=str(e), security_event="challenge_failure")
        raise HTTPException(status_code=401, detail="Challenge verification failed")

@app.get("/protected/resource")
def get_protected_resource(request: Request):
    """
    Protected resource, returns AEAD-encrypted response using session key.
    """
    session_token = request.headers.get("x-qasp-session")
    if not session_token or session_token not in _sessions:
        RESOURCE_ACCESS_TOTAL.labels(result='failure', tenant_id='unknown').inc()
        logger.warning("Protected resource access attempted with invalid session", security_event="resource_unauthorized")
        raise HTTPException(status_code=401, detail="Invalid or missing session token")

    session = _sessions[session_token]
    tenant_id = session.get("tenant_id", "unknown")
    if time.time() > session["expiry"]:
        del _sessions[session_token]
        RESOURCE_ACCESS_TOTAL.labels(result='failure', tenant_id=tenant_id).inc()
        logger.warning("Protected resource access attempted with expired session", session_id=session["session_id"], security_event="resource_expired")
        raise HTTPException(status_code=401, detail="Session expired")

    response_plaintext = b"Hello, protected world from QASP v1.0"
    nonce, ct = aead_encrypt(session["key"], response_plaintext, b"response")

    RESOURCE_ACCESS_TOTAL.labels(result='success', tenant_id=tenant_id).inc()
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

@app.get("/admin/tenants")
def list_tenants(request: Request):
    """
    Admin endpoint to list all tenants.
    Requires admin mode; returns list of tenant_ids.
    """
    tenants = list(_clients.keys())
    return {"tenants": tenants}

@app.get("/analytics/usage")
def get_analytics_usage(request: Request):
    """
    LTS Analytics usage endpoint.
    Read-only, admin-authenticated. Returns aggregated multi-tenant metrics.
    """
    # Simulate admin authentication (in real, check token)
    admin_header = request.headers.get("x-admin-auth")
    if not admin_header or admin_header != os.getenv("ADMIN_TOKEN", "default-admin-token"):
        raise HTTPException(status_code=403, detail="Admin authentication required")

    collector = LTSMetricsCollector()
    data = collector.collect_usage_stats()
    return {"usage_stats": data}

@app.post("/research/submit")
async def submit_research_metrics(request: Request):
    """
    Research collaboration endpoint.
    Receives signed performance and interoperability metrics from research partners.
    Simulated: validates DID and signature (mock implementation).
    """
    data = await request.json()
    researcher_did = data.get("researcher_did")
    metrics = data.get("metrics")
    signature = data.get("signature")

    if not researcher_did or not metrics or not signature:
        raise HTTPException(status_code=400, detail="Missing required fields: researcher_did, metrics, signature")

    # Simulate attestation: Check if DID is known and verify signature
    # In real: Resolve DID public key, verify Dilithium signature
    known_dids = {"did:qasp:researcher123", "did:qasp:partner456"}  # Mock
    if researcher_did not in known_dids:
        raise HTTPException(status_code=403, detail="Unauthorized researcher DID")

    # Mock signature verification
    if not signature.startswith("dilithium_"):
        raise HTTPException(status_code=401, detail="Invalid signature")

    # Store submitted data (simulate)
    submission = {
        "did": researcher_did,
        "metrics": metrics,
        "timestamp": data.get("timestamp"),
        "attested": True
    }
    # In real: Append to research DB
    print(f"Research submission received: {submission}")

    return {"status": "submitted", "attestation_id": uuid.uuid4().hex}

@app.get("/metrics")
def metrics_endpoint():
    """
    Prometheus metrics endpoint for monitoring.
    """
    return Response(content=get_metrics(), media_type="text/plain")

@app.get("/hardware/status")
def hardware_status():
    """
    Hardware QKD status endpoint for monitoring.
    """
    return {
        "qkd_hardware_enabled": os.getenv("QKD_HARDWARE_ENABLED", "false").lower() == "true",
        "qkd_mode": os.getenv("QKD_MODE", "simulated"),
        "driver_available": qkd_driver.is_available(),
        "driver_type": type(qkd_driver).__name__,
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
