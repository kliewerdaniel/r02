import os
import hashlib
import uuid
import base64
from fastapi import FastAPI
from typing import Dict

app = FastAPI(title="Mock QKD Service", version="0.1.0")

# Modes: 'sim' for random bytes, 'mock-hardware' for deterministic pseudo
MODE = os.getenv("QKD_MODE", "sim")

# In-memory key store (do not persist to disk)
_keys: Dict[str, bytes] = {}
_session_counter = 0

@app.get("/qkd/session")
def get_qkd_session() -> Dict[str, str]:
    """
    Simulate QKD session key exchange.
    Returns a new session key ID and base64-encoded key.
    In production, replace with hardware QKD provider API.
    """
    global _session_counter
    _session_counter += 1

    if MODE == "sim":
        key = os.urandom(32)  # Strong random, 256-bit
    elif MODE == "mock-hardware":
        # Deterministic for reproducible tests
        key = hashlib.sha256(b"mock-qkd-key-" + str(_session_counter).encode()).digest()
    else:
        raise ValueError(f"Invalid QKD mode: {MODE}")

    key_id = str(uuid.uuid4())
    _keys[key_id] = key

    # Note: In sensitive logs, mask the key value
    encoded_key = base64.b64encode(key).decode()
    return {"qkd_key_id": key_id, "qkd_key": encoded_key}

@app.delete("/qkd/session/{key_id}")
def delete_qkd_session(key_id: str):
    """
    Delete a QKD session key from memory.
    """
    if key_id in _keys:
        del _keys[key_id]
        return {"status": "deleted"}
    return {"status": "not found"}, 404

def get_key_by_id(key_id: str) -> bytes:
    """
    Internal function to retrieve key by ID (for server use).
    """
    return _keys.get(key_id)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
