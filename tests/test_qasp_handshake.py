import pytest
import base64
import os
from cryptography.hazmat.primitives import hashes
from src.qasp.crypto import PQCKEM, PQCSign, derive_session_key, aead_encrypt, aead_decrypt
from src.server.main import app
from fastapi.testclient import TestClient
from unittest.mock import patch

# Unit tests

def test_pqckem_keypair_encaps():
    alam = PQCKEM()
    pub = alam.generate_keypair()
    assert pub is not None

    bob = PQCKEM()
    ciphertext, shared_secret_alam = bob.encapsulate(pub)

    shared_secret_alice = alam.decapsulate(ciphertext)
    assert shared_secret_alam == shared_secret_alice

def test_pqcsign_keys():
    sig = PQCSign()
    pub = sig.generate_keypair()
    assert pub is not None

    message = b"test message"
    signature = sig.sign(message)
    assert signature is not None

    assert PQCSign.verify(pub, message, signature)

def test_derive_session_key_consistency():
    shared_secret = os.urandom(32)
    qkd_key = os.urandom(32)
    qrng = None
    client_nonce = os.urandom(16)
    server_nonce = os.urandom(16)

    # Client side (has shared_secret from encapsulation)
    key_client = derive_session_key(shared_secret, qkd_key, qrng, client_nonce, server_nonce)

    # Server side (has same inputs)
    key_server = derive_session_key(shared_secret, qkd_key, qrng, client_nonce, server_nonce)

    assert key_client == key_server

def test_aead_encrypt_decrypt():
    key = os.urandom(32)
    plaintext = b"Hello, world!"
    aad = b"aad data"

    nonce, ct = aead_encrypt(key, plaintext, aad)
    decrypted = aead_decrypt(key, nonce, ct, aad)

    assert decrypted == plaintext

# Integration tests

@pytest.fixture
def client():
    return TestClient(app)

def test_integration_qasp_handshake(client):
    # Register client
    client_kem = PQCKEM()
    client_pub_kem = client_kem.generate_keypair()
    client_sig = PQCSign()
    client_pub_sig = client_sig.generate_keypair()

    register_resp = client.post("/qasp/register", json={
        "client_id": "test",
        "pub_kem": base64.b64encode(client_pub_kem).decode(),
        "pub_sig": base64.b64encode(client_pub_sig).decode(),
    })
    assert register_resp.status_code == 200

    # Get server pub
    pubs_resp = client.get("/public-keys")
    assert pubs_resp.status_code == 200
    server_pub_kem = base64.b64decode(pubs_resp.json()["pub_kem"])

    # Init session (client side simulation)
    session_kem = PQCKEM()
    ciphertext, shared_secret = session_kem.encapsulate(server_pub_kem)
    client_nonce = os.urandom(16)

    init_resp = client.post("/qasp/init", json={
        "client_id": "test",
        "kem_encaps": base64.b64encode(ciphertext).decode(),
        "client_nonce": base64.b64encode(client_nonce).decode(),
        "supported_qkd": False,
    })
    assert init_resp.status_code == 200
    init_data = init_resp.json()
    session_token = init_data["session_token"]
    server_nonce = base64.b64decode(init_data["server_nonce"])

    # Derive key client side
    session_key = derive_session_key(shared_secret, None, None, client_nonce, server_nonce)

    # Access protected resource
    prot_resp = client.get("/protected/resource", headers={"x-qasp-session": session_token})
    assert prot_resp.status_code == 200
    prot_data = prot_resp.json()

    nonce = base64.b64decode(prot_data["nonce"])
    ct = base64.b64decode(prot_data["ciphertext"])
    decrypted = aead_decrypt(session_key, nonce, ct, b"response")
    assert decrypted == b"Hello, protected world from QASP v0.1"

# PQC compatibility smoke test (placeholder)
def test_then_liboqs_smoke():
    # In CI, this could run the liboqs examples
    # For now, just test that oqs import works and we can create objects
    import oqs
    # Simple test that liboqs is available
    assert hasattr(oqs, 'KeyEncapsulation')
    assert hasattr(oqs, 'Signature')
