"""
HashiCorp Vault HSM Adapter for QASP v1.0.

This module provides an HSM implementation that integrates with HashiCorp Vault
for secure key storage and cryptographic operations in production environments.

The adapter uses HashiCorp Vault for:
- Secure key storage and retrieval
- Encryption/decryption operations via Transit secrets engine
- Key rotation management
- Access control via Vault policies

Security considerations:
- Keys are managed entirely within Vault
- All operations require proper Vault authentication
- Uses envelope encryption pattern with Vault's transit engine
- Supports multi-tenant key isolation via path-based access

Prerequisites:
- Vault server running and accessible
- Transit secrets engine enabled
- Authentication configured (token-based)
- Environment variables: VAULT_ADDR, VAULT_TOKEN
"""

import logging
import os
import base64
import json
from typing import Dict, List, Optional

try:
    import hvac
    VAULT_AVAILABLE = True
except ImportError:
    VAULT_AVAILABLE = False
    hvac = None

from ..abstract_store import KeyStoreABC

logger = logging.getLogger(__name__)


class HashiCorpVaultAdapter(KeyStoreABC):
    """
    HashiCorp Vault-based HSM adapter for production key management.

    This adapter provides secure key storage using Vault's transit secrets engine
    for cryptographic operations and key management.

    Security model:
    - Keys are generated and stored within Vault
    - All cryptographic operations happen within Vault
    - Envelope encryption uses Vault-managed data encryption keys
    - Tenant isolation achieved through key naming conventions and policies
    """

    def __init__(self):
        """Initialize HashiCorp Vault adapter."""
        if not VAULT_AVAILABLE:
            raise ImportError("hvac is required for HashiCorp Vault adapter. Install with: pip install hvac")

        self.vault_url = os.getenv("VAULT_ADDR")
        self.vault_token = os.getenv("VAULT_TOKEN")

        if not self.vault_url:
            raise ValueError("VAULT_ADDR environment variable must be set for Vault adapter")

        if not self.vault_token:
            raise ValueError("VAULT_TOKEN environment variable must be set for Vault adapter")

        try:
            self.client = hvac.Client(url=self.vault_url, token=self.vault_token)

            # Test connection
            if not self.client.is_authenticated():
                raise ValueError("Vault authentication failed")

            # Check if transit engine is enabled
            if not self.client.sys.is_enabled_secrets_engine('transit')['data']['enabled']:
                raise ValueError("Vault transit secrets engine is not enabled")

            logger.info(
                "HashiCorp Vault adapter initialized successfully",
                extra={
                    "vault_url": self.vault_url,
                    "security_event": "vault_adapter_init"
                }
            )

        except Exception as e:
            raise ValueError(f"Failed to initialize Vault adapter: {e}")

    def _get_tenant_key_path(self, tenant_id: str, client_id: str, key_type: str) -> str:
        """Generate a unique key path for tenant-scoped keys in Vault."""
        return f"qasp/{tenant_id}/{client_id}/{key_type}"

    def _ensure_tenant_key_exists(self, key_path: str) -> bool:
        """
        Ensure a key exists in Vault's transit engine.

        Args:
            key_path: The key path in Vault

        Returns:
            True if key exists or was created, False otherwise
        """
        try:
            # Check if key exists
            response = self.client.secrets.transit.read_key(key_path)
            return response is not None
        except Exception:
            # Key doesn't exist, create it
            try:
                response = self.client.secrets.transit.create_key(
                    name=key_path,
                    key_type='aes256-gcm96',
                    derived=False
                )
                return response['data']['created'] == True
            except Exception as e:
                logger.error(f"Failed to create Vault key {key_path}: {e}")
                return False

    def store_private_key(self, tenant_id: str, client_id: str, key_type: str, key_bytes: bytes) -> bool:
        """
        Store a private key encrypted using Vault's transit engine.

        The key is encrypted using a Vault-managed data encryption key with AES-GCM.
        The encrypted data is stored in the database along with Vault metadata.

        Args:
            tenant_id: Unique identifier for the tenant
            client_id: Unique identifier for the client
            key_type: Type of key ('kem' or 'sign')
            key_bytes: The private key data as bytes

        Returns:
            True if storage was successful, False otherwise
        """
        try:
            key_path = self._get_tenant_key_path(tenant_id, client_id, key_type)

            # Ensure the key exists in Vault
            if not self._ensure_tenant_key_exists(key_path):
                logger.error(f"Failed to ensure Vault key exists: {key_path}")
                return False

            # Encrypt the private key using Vault
            plaintext = base64.b64encode(key_bytes).decode()
            encrypt_data = {
                'plaintext': plaintext
            }

            response = self.client.secrets.transit.encrypt_data(
                name=key_path,
                plaintext=plaintext
            )

            encrypted_data = response['data']['ciphertext']

            # Store encrypted data in database
            from ...db.session import DatabaseSession
            from ...db.models import KeyRecord

            with DatabaseSession() as db:
                key_record = KeyRecord(
                    tenant_id=tenant_id,
                    key_id=key_path,
                    key_type=key_type,
                    key_algorithm="Vault-AES256-GCM",
                    encrypted_key_data=encrypted_data,
                    key_nonce="",  # Vault handles nonce internally
                    key_tag=""   # Vault handles authentication tag internally
                )
                db.add(key_record)

                # Store Vault key path in metadata
                key_record.key_metadata = json.dumps({
                    'vault_key_path': key_path,
                    'vault_key_version': response['data']['key_version']
                })

                db.commit()

            logger.info(
                f"Private key stored successfully in HashiCorp Vault",
                extra={
                    "tenant_id": tenant_id,
                    "client_id": client_id,
                    "key_type": key_type,
                    "key_size": len(key_bytes),
                    "vault_key_path": key_path,
                    "security_event": "vault_key_storage"
                }
            )
            return True

        except Exception as e:
            logger.error(
                f"Failed to store private key with HashiCorp Vault",
                extra={
                    "tenant_id": tenant_id,
                    "client_id": client_id,
                    "key_type": key_type,
                    "error": str(e),
                    "security_event": "vault_key_storage_failure"
                }
            )
            return False

    def get_private_key(self, tenant_id: str, client_id: str, key_type: str) -> Optional[bytes]:
        """
        Retrieve and decrypt a private key from HashiCorp Vault.

        Args:
            tenant_id: Unique identifier for the tenant
            client_id: Unique identifier for the client
            key_type: Type of key ('kem' or 'sign')

        Returns:
            The decrypted private key bytes if found and decryption successful, None otherwise
        """
        try:
            key_path = self._get_tenant_key_path(tenant_id, client_id, key_type)

            from ...db.session import DatabaseSession
            from ...db.models import KeyRecord

            with DatabaseSession() as db:
                key_record = db.query(KeyRecord).filter_by(
                    tenant_id=tenant_id,
                    key_id=key_path,
                    is_active=True
                ).first()

                if not key_record:
                    logger.warning(
                        f"Private key not found in HashiCorp Vault",
                        extra={
                            "tenant_id": tenant_id,
                            "client_id": client_id,
                            "key_type": key_type,
                            "security_event": "vault_key_retrieval_not_found"
                        }
                    )
                    return None

                # Decrypt using Vault
                response = self.client.secrets.transit.decrypt_data(
                    name=key_path,
                    ciphertext=key_record.encrypted_key_data
                )

                plaintext = response['data']['plaintext']
                decrypted_key = base64.b64decode(plaintext)

                logger.info(
                    f"Private key retrieved successfully from HashiCorp Vault",
                    extra={
                        "tenant_id": tenant_id,
                        "client_id": client_id,
                        "key_type": key_type,
                        "key_size": len(decrypted_key),
                        "security_event": "vault_key_retrieval"
                    }
                )
                return decrypted_key

        except Exception as e:
            logger.error(
                f"Failed to retrieve and decrypt private key from HashiCorp Vault",
                extra={
                    "tenant_id": tenant_id,
                    "client_id": client_id,
                    "key_type": key_type,
                    "error": str(e),
                    "security_event": "vault_key_retrieval_failure"
                }
            )
            return None

    def list_keys(self, tenant_id: str) -> List[Dict[str, str]]:
        """
        List all stored keys for a given tenant in HashiCorp Vault.

        Args:
            tenant_id: Unique identifier for the tenant

        Returns:
            List of dictionaries with key information
        """
        try:
            from ...db.session import DatabaseSession
            from ...db.models import KeyRecord

            keys = []
            with DatabaseSession() as db:
                key_records = db.query(KeyRecord).filter(
                    KeyRecord.key_id.like(f"qasp/{tenant_id}/%"),
                    KeyRecord.is_active == True
                ).all()

                for record in key_records:
                    # Parse client_id and key_type from key_id
                    parts = record.key_id.split('/')
                    if len(parts) >= 4 and parts[0] == 'qasp' and parts[1] == tenant_id:
                        client_id, key_type = parts[2], parts[3]
                        keys.append({
                            "client_id": client_id,
                            "key_type": key_type,
                            "key_algorithm": record.key_algorithm,
                            "created_at": record.created_at.isoformat() if record.created_at else None
                        })

            logger.info(f"Key listing requested for tenant {tenant_id}: {len(keys)} keys found")
            return keys

        except Exception as e:
            logger.error(
                f"Failed to list keys for tenant {tenant_id}",
                extra={
                    "tenant_id": tenant_id,
                    "error": str(e),
                    "security_event": "vault_key_list_failure"
                }
            )
            return []

    def rotate_key(self, tenant_id: str, client_id: str, key_type: str) -> bool:
        """
        Rotate a key using HashiCorp Vault's key rotation.

        Args:
            tenant_id: Unique identifier for the tenant
            client_id: Unique identifier for the client
            key_type: Type of key to rotate

        Returns:
            True if rotation was successful, False otherwise
        """
        try:
            key_path = self._get_tenant_key_path(tenant_id, client_id, key_type)

            # Rotate the key in Vault
            response = self.client.secrets.transit.rotate_key(name=key_path)

            if response['data']['created'] == True:
                logger.info(
                    f"Key rotated successfully in HashiCorp Vault",
                    extra={
                        "tenant_id": tenant_id,
                        "client_id": client_id,
                        "key_type": key_type,
                        "vault_key_path": key_path,
                        "new_key_version": response['data']['key_version'],
                        "security_event": "vault_key_rotation_success"
                    }
                )
                return True
            else:
                logger.warning(
                    f"Key rotation did not create new version in HashiCorp Vault",
                    extra={
                        "tenant_id": tenant_id,
                        "client_id": client_id,
                        "key_type": key_type,
                        "vault_key_path": key_path,
                        "security_event": "vault_key_rotation_no_change"
                    }
                )
                return False

        except Exception as e:
            logger.error(
                f"Failed to rotate key in HashiCorp Vault",
                extra={
                    "tenant_id": tenant_id,
                    "client_id": client_id,
                    "key_type": key_type,
                    "error": str(e),
                    "security_event": "vault_key_rotation_failure"
                }
            )
            return False

    def sign_data(self, tenant_id: str, client_id: str, key_type: str, data: bytes) -> Optional[bytes]:
        """
        Sign data using HashiCorp Vault.

        This method supports asymmetric signing if Vault transit engine is configured
        with appropriate key types (RSA, ECDSA, ED25519).

        Args:
            tenant_id: Unique identifier for the tenant
            client_id: Unique identifier for the client
            key_type: Type of key (must support signing)
            data: Data to sign

        Returns:
            Signature bytes, or None if signing failed
        """
        try:
            key_path = self._get_tenant_key_path(tenant_id, client_id, key_type)

            # For signing, we need to use base64 encoded input
            input_data = base64.b64encode(data).decode()
            sign_data = {
                'input': input_data,
                'signature_algorithm': 'pkcs1v15' if key_type == 'rsa' else 'pure'  # Adjust based on key type
            }

            response = self.client.secrets.transit.sign_data(
                name=key_path,
                input=input_data,
                signature_algorithm='pkcs1v15',
                hash_algorithm='sha2-256'
            )

            signature_b64 = response['data']['signature']
            # Remove vault signature prefix (vault:v1:...)
            actual_signature = signature_b64.split(':', 2)[-1]
            signature_bytes = base64.b64decode(actual_signature)

            logger.info(
                f"Data signed successfully using HashiCorp Vault",
                extra={
                    "tenant_id": tenant_id,
                    "client_id": client_id,
                    "key_type": key_type,
                    "data_size": len(data),
                    "signature_size": len(signature_bytes),
                    "security_event": "vault_signing_success"
                }
            )

            return signature_bytes

        except Exception as e:
            logger.error(
                f"Failed to sign data using HashiCorp Vault",
                extra={
                    "tenant_id": tenant_id,
                    "client_id": client_id,
                    "key_type": key_type,
                    "error": str(e),
                    "security_event": "vault_signing_failure"
                }
            )
            return None

    def verify_signature(self, tenant_id: str, client_id: str, key_type: str, data: bytes, signature: bytes) -> bool:
        """
        Verify a signature using HashiCorp Vault.

        Args:
            tenant_id: Unique identifier for the tenant
            client_id: Unique identifier for the client
            key_type: Type of key used for signing
            data: Original data that was signed
            signature: Signature to verify

        Returns:
            True if signature is valid, False otherwise
        """
        try:
            key_path = self._get_tenant_key_path(tenant_id, client_id, key_type)

            # Prepare signature in Vault format (vault:v1:...)
            signature_b64 = base64.b64encode(signature).decode()
            vault_signature = f"vault:v1:{signature_b64}"

            input_data = base64.b64encode(data).decode()

            response = self.client.secrets.transit.verify_signed_data(
                name=key_path,
                input=input_data,
                signature=vault_signature,
                signature_algorithm='pkcs1v15',
                hash_algorithm='sha2-256'
            )

            is_valid = response['data']['valid']

            logger.info(
                f"Signature verification {'successful' if is_valid else 'failed'} using HashiCorp Vault",
                extra={
                    "tenant_id": tenant_id,
                    "client_id": client_id,
                    "key_type": key_type,
                    "data_size": len(data),
                    "signature_size": len(signature),
                    "signature_valid": is_valid,
                    "security_event": "vault_signature_verification"
                }
            )

            return is_valid

        except Exception as e:
            logger.error(
                f"Failed to verify signature using HashiCorp Vault",
                extra={
                    "tenant_id": tenant_id,
                    "client_id": client_id,
                    "key_type": key_type,
                    "error": str(e),
                    "security_event": "vault_signature_verification_failure"
                }
            )
            return False
