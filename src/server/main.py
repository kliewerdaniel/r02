import os
import time
import uuid
import base64
from typing import Dict, Optional
from fastapi import FastAPI, HTTPException, Request
import httpx
from src.qasp.crypto import PQCKEM, PQCSign, derive_session_key, aead_encrypt, aead_decrypt

# Check if HSM is enabled
HSM_ENABLED = os.getenv("HSM_ENABLED", "false").lower() == "true"

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

    return {
        "server_nonce": base64.b64encode(server_nonce).decode(),
        "session_token": session_token
    }

@app.post("/qasp/challenge")
async def challenge_session(request: Request):
    """
    Verify session token possession via decrypted challenge.
    """
    session_token = request.headers.get("x-qasp-session")
    if not session_token or session_token not in _sessions:
        raise HTTPException(status_code=401, detail="Invalid or missing session token")

    session = _sessions[session_token]
    if time.time() > session["expiry"]:
        del _sessions[session_token]
        raise HTTPException(status_code=401, detail="Session expired")

    data = await request.json()
    challenge_nonce_b64 = data.get("challenge_nonce")
    challenge_ct_b64 = data.get("challenge_ciphertext")

    if not challenge_nonce_b64 or not challenge_ct_b64:
        raise HTTPException(status_code=400, detail="Missing challenge data")

    try:
        nonce = base64.b64decode(challenge_nonce_b64)
        ct = base64.b64decode(challenge_ct_b64)
        challenge_bytes = aead_decrypt(session["key"], nonce, ct, b"challenge")
        challenge_text = challenge_bytes.decode()
        if challenge_text != "challenge-test":
            raise Exception("Invalid challenge")
        return {"challenge_verified": True}
    except Exception as e:
        raise HTTPException(status_code=401, detail="Challenge verification failed")

@app.get("/protected/resource")
def get_protected_resource(request: Request):
    """
    Protected resource, returns AEAD-encrypted response using session key.
    """
    session_token = request.headers.get("x-qasp-session")
    if not session_token or session_token not in _sessions:
        raise HTTPException(status_code=401, detail="Invalid or missing session token")

    session = _sessions[session_token]
    if time.time() > session["expiry"]:
        del _sessions[session_token]
        raise HTTPException(status_code=401, detail="Session expired")

    response_plaintext = b"Hello, protected world from QASP v0.1"
    nonce, ct = aead_encrypt(session["key"], response_plaintext, b"response")

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
    return {"keys": keys}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
