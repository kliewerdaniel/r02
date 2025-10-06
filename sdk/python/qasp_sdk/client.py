"""
QASP v0.2 Python Client SDK - Client Implementation

This module provides the QASPClient class for interacting with QASP v0.2 servers.
It handles cryptographic operations, message serialization, and protocol flow.
"""

import os
import base64
import httpx
from typing import Optional, Dict, Any
import structlog

from ...src.qasp.crypto import PQCKEM, PQCSign, derive_session_key, aead_encrypt, aead_decrypt
from ...src.interop.qasp_interop import serialize_handshake, deserialize_handshake

logger = structlog.get_logger(__name__)


class QASPClient:
    """
    QASP v0.2 Client SDK

    Minimal client implementation for QASP v0.2 protocol.
    Handles client registration, session initialization, and secure communication.

    Attributes:
        server_url: Base URL of the QASP server
        tenant_id: Tenant identifier for multi-tenant isolation
        client_id: Client identifier
        kem: Post-quantum KEM instance for key exchange
        sign: Post-quantum signature instance for authentication
        session_token: Current session token (if active)
        session_key: Current session key (if active)
    """

    def __init__(self, server_url: str, tenant_id: Optional[str] = "default"):
        """
        Initialize the QASP client.

        Args:
            server_url: Base URL of the QASP server (e.g., "http://localhost:8000")
            tenant_id: Tenant identifier for isolation (defaults to "default")
        """
        self.server_url = server_url.rstrip('/')
        self.tenant_id = tenant_id
        self.client_id = None
        self.kem: Optional[PQCKEM] = None
        self.sign: Optional[PQCSign] = None
        self.session_token: Optional[str] = None
        self.session_key: Optional[bytes] = None

        logger.info("QASPClient initialized",
                   server_url=server_url,
                   tenant_id=tenant_id)

    def register_client(self, client_id: str) -> bool:
        """
        Register this client with the server.

        Generates a new keypair and registers the public keys with the server.
        This is typically done out-of-band before normal operation.

        Args:
            client_id: Unique identifier for this client

        Returns:
            True if registration successful, False otherwise
        """
        try:
            self.client_id = client_id

            # Generate keypairs
            self.kem = PQCKEM(tenant_id=self.tenant_id)
            self.kem.generate_keypair()

            self.sign = PQCSign(tenant_id=self.tenant_id)
            self.sign.generate_keypair()

            # Get public keys
            kem_pub = base64.b64encode(self.kem.export_public()).decode()
            sign_pub = base64.b64encode(self.sign.export_public()).decode()

            # Register with server
            register_data = {
                "client_id": client_id,
                "tenant_id": self.tenant_id,
                "pub_kem": kem_pub,
                "pub_sig": sign_pub
            }

            response = httpx.post(f"{self.server_url}/qasp/register", json=register_data)
            response.raise_for_status()

            logger.info("Client registered successfully",
                       client_id=client_id,
                       tenant_id=self.tenant_id)
            return True

        except Exception as e:
            logger.error("Client registration failed",
                        client_id=client_id,
                        tenant_id=self.tenant_id,
                        error=str(e))
            return False

    def init_handshake(self, use_qkd: bool = False) -> Optional[str]:
        """
        Initialize a QASP handshake session.

        Performs the initial key exchange to establish a shared session key.

        Args:
            use_qkd: Whether to request quantum key distribution (if available)

        Returns:
            Session token if successful, None otherwise
        """
        if not self.client_id or not self.kem:
            logger.error("Client not registered or initialized")
            return None

        try:
            # Get server's public keys
            response = httpx.get(f"{self.server_url}/public-keys")
            response.raise_for_status()
            server_keys = response.json()

            server_kem_pub = base64.b64decode(server_keys["pub_kem"])

            # Generate client nonce
            client_nonce = os.urandom(16)

            # Encapsulate shared secret
            ciphertext, shared_secret = self.kem.encapsulate(server_kem_pub)

            # Prepare handshake message
            handshake_data = {
                "type": "handshake_init",
                "client_id": self.client_id,
                "tenant_id": self.tenant_id,
                "kem_encaps": base64.b64encode(ciphertext).decode(),
                "client_nonce": base64.b64encode(client_nonce).decode(),
                "supported_qkd": use_qkd
            }

            # Serialize to canonical JSON
            serialized = serialize_handshake(handshake_data)

            # Send to server
            response = httpx.post(f"{self.server_url}/qasp/init", content=serialized)
            response.raise_for_status()

            result = response.json()

            # Extract server nonce and derive session key
            server_nonce = base64.b64decode(result["server_nonce"])
            qkd_key = None  # QKD not implemented in SDK yet

            self.session_key = derive_session_key(
                shared_secret, qkd_key, None, client_nonce, server_nonce
            )
            self.session_token = result["session_token"]

            logger.info("Handshake initialized successfully",
                       client_id=self.client_id,
                       tenant_id=self.tenant_id,
                       session_token=self.session_token[:16] + "...")
            return self.session_token

        except Exception as e:
            logger.error("Handshake initialization failed",
                        client_id=self.client_id,
                        tenant_id=self.tenant_id,
                        error=str(e))
            return None

    def challenge(self) -> bool:
        """
        Perform challenge-response authentication.

        Verifies possession of the session token through encrypted challenge.

        Returns:
            True if challenge successful, False otherwise
        """
        if not self.session_token or not self.session_key:
            logger.error("No active session")
            return False

        try:
            challenge_data = {
                "type": "challenge_request",
                "challenge_nonce": base64.b64encode(os.urandom(12)).decode(),
                "challenge_ciphertext": base64.b64encode(os.urandom(32)).decode()  # Placeholder
            }

            serialized = serialize_handshake(challenge_data)

            headers = {"x-qasp-session": self.session_token}
            response = httpx.post(f"{self.server_url}/qasp/challenge",
                                content=serialized,
                                headers=headers)
            response.raise_for_status()

            result = response.json()
            verified = result.get("challenge_verified", False)

            logger.info("Challenge verification completed",
                       client_id=self.client_id,
                       tenant_id=self.tenant_id,
                       verified=verified)
            return verified

        except Exception as e:
            logger.error("Challenge failed",
                        client_id=self.client_id,
                        tenant_id=self.tenant_id,
                        error=str(e))
            return False

    def request_resource(self, resource_path: str = "/protected/resource") -> Optional[Dict[str, Any]]:
        """
        Request a protected resource using the current session.

        Args:
            resource_path: Path to the resource endpoint

        Returns:
            Decrypted resource data if successful, None otherwise
        """
        if not self.session_token or not self.session_key:
            logger.error("No active session")
            return None

        try:
            headers = {"x-qasp-session": self.session_token}
            response = httpx.get(f"{self.server_url}{resource_path}", headers=headers)
            response.raise_for_status()

            # Parse encrypted response
            data = response.json()
            nonce = base64.b64decode(data["nonce"])
            ciphertext = base64.b64decode(data["ciphertext"])

            # Decrypt
            plaintext = aead_decrypt(self.session_key, nonce, ciphertext, b"response")
            resource_data = plaintext.decode()

            logger.info("Resource accessed successfully",
                       client_id=self.client_id,
                       tenant_id=self.tenant_id,
                       resource=resource_path)

            return {"plaintext": resource_data, "metadata": data}

        except Exception as e:
            logger.error("Resource request failed",
                        client_id=self.client_id,
                        tenant_id=self.tenant_id,
                        resource=resource_path,
                        error=str(e))
            return None

    def close_session(self) -> None:
        """Close the current session."""
        self.session_token = None
        self.session_key = None
        logger.info("Session closed",
                   client_id=self.client_id,
                   tenant_id=self.tenant_id)
