import os
import base64
import httpx
from src.qasp.crypto import PQCKEM, PQCSign, derive_session_key, aead_encrypt, aead_decrypt

SERVER_URL = os.getenv("SERVER_URL", "http://localhost:8000")

def main():
    print("Starting QASP v0.1 demo client...")

    # Generate client keys
    client_kem = PQCKEM()
    client_pub_kem = client_kem.generate_keypair()

    client_sig = PQCSign()
    client_pub_sig = client_sig.generate_keypair()

    print("Generated client keys")

    # Register client
    register_data = {
        "client_id": "demo",
        "pub_kem": base64.b64encode(client_pub_kem).decode(),
        "pub_sig": base64.b64encode(client_pub_sig).decode(),
    }
    resp = httpx.post(f"{SERVER_URL}/qasp/register", json=register_data)
    resp.raise_for_status()
    print(f"Registered client: {resp.json()}")

    # Get server public keys
    resp = httpx.get(f"{SERVER_URL}/public-keys")
    resp.raise_for_status()
    server_pubs = resp.json()
    server_pub_kem = base64.b64decode(server_pubs["pub_kem"])
    print("Retrieved server public keys")

    # Initialize session
    # Create new kem instance for encapsulation
    session_kem = PQCKEM()
    ciphertext, shared_secret = session_kem.encapsulate(server_pub_kem)
    client_nonce = os.urandom(16)

    init_data = {
        "client_id": "demo",
        "kem_encaps": base64.b64encode(ciphertext).decode(),
        "client_nonce": base64.b64encode(client_nonce).decode(),
        "supported_qkd": False,  # No QKD for demo
    }
    resp = httpx.post(f"{SERVER_URL}/qasp/init", json=init_data)
    resp.raise_for_status()
    init_resp = resp.json()
    session_token = init_resp["session_token"]
    server_nonce_b64 = init_resp["server_nonce"]
    server_nonce = base64.b64decode(server_nonce_b64)

    print(f"Initialized session, token: {session_token[:20]}...")

    # Derive session key (simulate what server does)
    session_key = derive_session_key(shared_secret, None, None, client_nonce, server_nonce)
    print("Derived session key")

    # Optional: Challenge (commented out for simplicity)
    # challenge_text = b"challenge-test"
    # challenge_nonce, challenge_ct = aead_encrypt(session_key, challenge_text, b"challenge")
    # challenge_data = {
    #     "challenge_nonce": base64.b64encode(challenge_nonce).decode(),
    #     "challenge_ciphertext": base64.b64encode(challenge_ct).decode(),
    # }
    # headers = {"x-qasp-session": session_token}
    # resp = httpx.post(f"{SERVER_URL}/qasp/challenge", json=challenge_data, headers=headers)
    # resp.raise_for_status()
    # print(f"Challenge verified: {resp.json()}")

    # Access protected resource
    headers = {"x-qasp-session": session_token}
    resp = httpx.get(f"{SERVER_URL}/protected/resource", headers=headers)
    resp.raise_for_status()
    prot_resp = resp.json()

    nonce = base64.b64decode(prot_resp["nonce"])
    ct = base64.b64decode(prot_resp["ciphertext"])
    plaintext = aead_decrypt(session_key, nonce, ct, b"response")
    print(f"Protected resource response: {plaintext.decode()}")

    print("Demo completed successfully!")

if __name__ == "__main__":
    main()
