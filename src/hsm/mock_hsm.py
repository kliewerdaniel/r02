"""
Mock HSM implementation using in-memory encrypted key storage.

This module provides a mock Hardware Security Module (HSM) that stores PQC keys
encrypted at rest using AES-GCM encryption. The master key is derived from an
environment variable for demonstration purposes. In production, this would be
replaced with a real HSM or KMS integration.

All key operations are logged with INFO and SECURITY levels for audit trails.
"""

import logging
import os
import hashlib
from typing import Dict, List, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .abstract_store import KeyStoreABC

logger = logging.getLogger(__name__)


class MockHSM(KeyStoreABC):
    """
    Mock HSM implementation with AES-GCM encrypted in-memory storage.

    This class provides a secure key vault that encrypts all stored keys using
    AES-GCM with a master key derived from the HSM_MASTER_SECRET environment
    variable. Keys are stored in an in-memory dictionary for simplicity and
    would be persisted to a secure database in a production system.

    Security considerations:
    - Master key is generated once at startup
    - Each key is encrypted with a unique nonce
    - Nonces and encrypted data are stored together
    - Logging provides audit trail for all operations
    """

    def __init__(self):
        """Initialize the mock HSM with AES-GCM encryption."""
        self._vault: Dict[str, Dict[str, bytes]] = {}  # tenant_id -> {key_id -> encrypted_data}
        self._master_key = self._derive_master_key()
        self._aesgcm = AESGCM(self._master_key)

        logger.info("MockHSM initialized with AES-GCM encryption")

    def _derive_master_key(self) -> bytes:
        """
        Derive the master AES-GCM key from environment variable.

        Returns:
            32-byte AES-GCM key

        Raises:
            ValueError: If HSM_MASTER_SECRET environment variable is not set
        """
        secret = os.getenv("HSM_MASTER_SECRET")
        if not secret:
            raise ValueError("HSM_MASTER_SECRET environment variable must be set")

        # Use SHA-256 to derive a 32-byte key from the secret
        master_key = hashlib.sha256(secret.encode('utf-8')).digest()
        logger.info("Master key derived successfully from HSM_MASTER_SECRET")
        return master_key

    def _generate_key_id(self, client_id: str, key_type: str) -> str:
        """Generate a unique key identifier."""
        return f"{client_id}:{key_type}"

    def store_private_key(self, tenant_id: str, client_id: str, key_type: str, key_bytes: bytes) -> bool:
        """
        Store a private key encrypted at rest.

        The key is encrypted using AES-GCM with a randomly generated nonce.
        The nonce is prepended to the encrypted data for storage.

        Args:
            tenant_id: Unique identifier for the tenant
            client_id: Unique identifier for the client
            key_type: Type of key ('kem' or 'sign')
            key_bytes: The private key data as bytes

        Returns:
            True if storage was successful, False otherwise
        """
        try:
            # Generate unique nonce for this encryption
            nonce = os.urandom(12)  # 96-bit nonce for AES-GCM

            # Encrypt the key
            encrypted_data = self._aesgcm.encrypt(nonce, key_bytes, None)

            # Store nonce + encrypted data as a single blob
            key_id = self._generate_key_id(client_id, key_type)
            if tenant_id not in self._vault:
                self._vault[tenant_id] = {}
            self._vault[tenant_id][key_id] = nonce + encrypted_data

            logger.info(
                f"Private key stored successfully",
                extra={
                    "tenant_id": tenant_id,
                    "client_id": client_id,
                    "key_type": key_type,
                    "key_size": len(key_bytes),
                    "security_event": "key_storage"
                }
            )
            return True

        except Exception as e:
            logger.error(
                f"Failed to store private key for client {client_id}",
                extra={
                    "tenant_id": tenant_id,
                    "client_id": client_id,
                    "key_type": key_type,
                    "error": str(e),
                    "security_event": "key_storage_failure"
                }
            )
            return False

    def get_private_key(self, tenant_id: str, client_id: str, key_type: str) -> Optional[bytes]:
        """
        Retrieve and decrypt a private key.

        Args:
            tenant_id: Unique identifier for the tenant
            client_id: Unique identifier for the client
            key_type: Type of key ('kem' or 'sign')

        Returns:
            The decrypted private key bytes if found and decryption successful, None otherwise
        """
        key_id = self._generate_key_id(client_id, key_type)

        if tenant_id not in self._vault or key_id not in self._vault[tenant_id]:
            logger.warning(
                f"Private key not found",
                extra={
                    "tenant_id": tenant_id,
                    "client_id": client_id,
                    "key_type": key_type,
                    "security_event": "key_retrieval_not_found"
                }
            )
            return None

        try:
            data = self._vault[tenant_id][key_id]

            # Extract nonce and encrypted data
            nonce = data[:12]
            encrypted_data = data[12:]

            # Decrypt the key
            decrypted_key = self._aesgcm.decrypt(nonce, encrypted_data, None)

            logger.info(
                f"Private key retrieved successfully",
                extra={
                    "tenant_id": tenant_id,
                    "client_id": client_id,
                    "key_type": key_type,
                    "key_size": len(decrypted_key),
                    "security_event": "key_retrieval"
                }
            )
            return decrypted_key

        except Exception as e:
            logger.error(
                f"Failed to retrieve and decrypt private key for client {client_id}",
                extra={
                    "tenant_id": tenant_id,
                    "client_id": client_id,
                    "key_type": key_type,
                    "error": str(e),
                    "security_event": "key_retrieval_failure"
                }
            )
            return None

    def list_keys(self, tenant_id: str) -> List[Dict[str, str]]:
        """
        List all stored keys for a given tenant.

        Args:
            tenant_id: Unique identifier for the tenant

        Returns:
            List of dictionaries with 'client_id' and 'key_type' for each key
        """
        keys = []
        if tenant_id in self._vault:
            for key_id in self._vault[tenant_id]:
                client_id, key_type = key_id.split(":", 1)
                keys.append({"client_id": client_id, "key_type": key_type})

        logger.info(f"Key listing requested for tenant {tenant_id}: {len(keys)} keys found")
        return keys

    def rotate_key(self, tenant_id: str, client_id: str, key_type: str) -> bool:
        """
        Rotate an existing private key.

        This method is not implemented in the mock HSM as it requires key generation
        logic that should be handled by the crypto module. Instead, this should be
        called with a new key to store, effectively rotating it.

        In a real HSM implementation, this would handle key generation internally.

        Args:
            tenant_id: Unique identifier for the tenant
            client_id: Unique identifier for the client
            key_type: Type of key to rotate ('kem' or 'sign')

        Returns:
            False - this operation should be handled by calling store_private_key with a new key
        """
        logger.warning(
            "Key rotation not supported by MockHSM implementation",
            extra={
                "tenant_id": tenant_id,
                "client_id": client_id,
                "key_type": key_type,
                "security_event": "key_rotation_denied"
            }
        )
        return False
