"""
Crypto-agility configuration for QASP.

This module provides environment-variable driven configuration for PQC algorithms,
allowing runtime switching between different cryptographic primitives without code changes.
This enables quantum-resistant upgrades and algorithm migrations.
"""

import os
from typing import Tuple
import oqs


# Default algorithms (NIST Round 3 selected)
DEFAULT_KEM_ALGORITHM = "Kyber512"
DEFAULT_SIGNATURE_ALGORITHM = "Dilithium3"

# Supported algorithms for crypto-agility
SUPPORTED_KEM_ALGORITHMS = [
    "Kyber512",    # NIST Level 1
    "Kyber768",    # NIST Level 3
    "Kyber1024",   # NIST Level 5  (for high-security deployments)
    "FrodoKEM-640-AES",  # Alternative Level 1
    "FrodoKEM-976-AES",  # Alternative Level 3
]

SUPPORTED_SIGNATURE_ALGORITHMS = [
    "Dilithium2",  # NIST Level 2
    "Dilithium3",  # NIST Level 3 (default for balance)
    "Dilithium5",  # NIST Level 5
    "Falcon-512",  # Alternative Level 1 (fast)
    "Falcon-1024", # Alternative Level 5
]


def get_kem_algorithm() -> str:
    """
    Get KEM algorithm from environment variable with fallback to default.

    Returns:
        The KEM algorithm name to use.
    """
    alg = os.getenv("KEM_ALG", DEFAULT_KEM_ALGORITHM)
    if alg not in SUPPORTED_KEM_ALGORITHMS:
        raise ValueError(f"Unsupported KEM algorithm: {alg}. Supported: {SUPPORTED_KEM_ALGORITHMS}")
    return alg


def get_signature_algorithm() -> str:
    """
    Get signature algorithm from environment variable with fallback to default.

    Returns:
        The signature algorithm name to use.
    """
    alg = os.getenv("SIG_ALG", DEFAULT_SIGNATURE_ALGORITHM)
    if alg not in SUPPORTED_SIGNATURE_ALGORITHMS:
        raise ValueError(f"Unsupported signature algorithm: {alg}. Supported: {SUPPORTED_SIGNATURE_ALGORITHMS}")
    return alg


def get_pqc_algorithms() -> Tuple[oqs.KeyEncapsulation, oqs.Signature]:
    """
    Factory function to create PQC algorithm instances based on configuration.

    This enables crypto-agility by allowing algorithm selection via environment variables.

    Returns:
        Tuple of (KeyEncapsulation, Signature) instances ready for use.

    Raises:
        ValueError: If configured algorithms are not supported or available.
    """
    kem_alg = get_kem_algorithm()
    sig_alg = get_signature_algorithm()

    # Validate that algorithms are enabled in the OQS library
    if kem_alg not in oqs.get_enabled_kem_mechanisms():
        raise ValueError(f"KEM algorithm {kem_alg} not enabled in OQS library")

    if sig_alg not in oqs.get_enabled_sig_mechanisms():
        raise ValueError(f"Signature algorithm {sig_alg} not enabled in OQS library")

    # Create and return the algorithm instances
    kem = oqs.KeyEncapsulation(kem_alg)
    sig = oqs.Signature(sig_alg)

    return kem, sig


def validate_crypto_config() -> bool:
    """
    Validate the current crypto configuration.

    This function can be called at startup to ensure all configured algorithms
    are available and functional before proceeding with cryptographic operations.

    Returns:
        True if configuration is valid, raises exception otherwise.
    """
    try:
        kem, sig = get_pqc_algorithms()

        # Test KEM functionality
        pub_key = kem.generate_keypair()
        ciphertext, shared_secret_server = kem.encap_secret(pub_key)
        shared_secret_client = kem.decap_secret(ciphertext)
        assert shared_secret_server == shared_secret_client

        # Test signature functionality
        pub_key_sig, sec_key_sig = sig.generate_keypair()
        test_message = b"QASP crypto test"
        signature = sig.sign(test_message)
        is_valid = sig.verify(test_message, signature, pub_key_sig)
        assert is_valid

        return True

    except Exception as e:
        raise ValueError(f"Crypto configuration validation failed: {e}")
