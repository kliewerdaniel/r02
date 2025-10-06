"""
Abstract interface for PQC key storage compatible with both mock HSM and real KMS backends.

This module defines the KeyStoreABC abstract base class that provides a standardized
interface for storing, retrieving, and managing post-quantum cryptography (PQC) keys.
Implementations can use in-memory storage, encrypted vaults, or external KMS services.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional


class KeyStoreABC(ABC):
    """
    Abstract base class for key storage operations.

    All PQC key management operations must implement this interface to ensure
    compatibility across different storage backends (mock HSM, hardware security
    modules, cloud KMS, etc.).

    Key types can include 'kem' for key encapsulation mechanism keys and 'sign'
    for digital signature keys.
    """

    @abstractmethod
    def store_private_key(self, client_id: str, key_type: str, key_bytes: bytes) -> bool:
        """
        Store a private key securely.

        Args:
            client_id: Unique identifier for the client
            key_type: Type of key ('kem' or 'sign')
            key_bytes: The private key data as bytes

        Returns:
            True if storage was successful, False otherwise
        """
        pass

    @abstractmethod
    def get_private_key(self, client_id: str, key_type: str) -> Optional[bytes]:
        """
        Retrieve a private key.

        Args:
            client_id: Unique identifier for the client
            key_type: Type of key ('kem' or 'sign')

        Returns:
            The private key bytes if found, None otherwise
        """
        pass

    @abstractmethod
    def list_keys(self) -> List[Dict[str, str]]:
        """
        List all stored keys.

        Returns:
            List of dictionaries with 'client_id' and 'key_type' for each key
        """
        pass

    @abstractmethod
    def rotate_key(self, client_id: str, key_type: str) -> bool:
        """
        Rotate an existing private key.

        This method should generate a new key and replace the existing one.
        The implementation must ensure the old key is securely destroyed or invalidated.

        Args:
            client_id: Unique identifier for the client
            key_type: Type of key to rotate ('kem' or 'sign')

        Returns:
            True if rotation was successful, False otherwise
        """
        pass
