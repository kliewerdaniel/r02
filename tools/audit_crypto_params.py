#!/usr/bin/env python3
"""
Cryptographic audit script for QASP Phase 2.

This script loads the Open Quantum Safe (OQS) library and performs an audit
of supported post-quantum cryptography (PQC) algorithms. It prints key
parameters, sizes, and NIST security categories for the algorithms used
in QASP, ensuring compliance and correctness of cryptographic parameters.

Output is designed to be captured as an artifact in CI/CD pipelines.
"""

import oqs
import sys
from datetime import datetime


def main():
    print("QASP Cryptographic Parameters Audit")
    print("=" * 50)
    print(f"Report generated: {datetime.utcnow().isoformat()}Z")
    print(f"Open Quantum Safe (OQS) version: {oqs.oqs_version()}")
    print(f"Python OQS version: {oqs.oqs_python_version()}")
    print()

    # Audit Key Encapsulation Mechanisms (KEMs)
    print("KEY ENCAPSULATION MECHANISMS (KEM):")
    print("-" * 40)

    kem_algorithms = [
        "Kyber512",
        "Kyber768",
        "Kyber1024",
        "FrodoKEM-640-AES",
        "FrodoKEM-976-AES",
        "FrodoKEM-1344-AES",
    ]

    for alg in kem_algorithms:
        if alg in oqs.get_enabled_kem_mechanisms():
            try:
                kem = oqs.KeyEncapsulation(alg)
                details = kem.details

                nist_level = get_nist_security_level(alg)

                print(f"Algorithm: {alg}")
                print(f"  NIST Security Level: {nist_level}")
                print(f"  Public Key Length: {details['public_key_length']} bytes")
                print(f"  Secret Key Length: {details['secret_key_length']} bytes")
                print(f"  Ciphertext Length: {details['ciphertext_length']} bytes")
                print(f"  Shared Secret Length: {details['shared_secret_length']} bytes")
                print(f"  Algorithm Version: {details.get('version', 'N/A')}")

                # Test basic functionality
                pub_key = kem.generate_keypair()
                ciphertext, shared_secret_server = kem.encap_secret(pub_key)
                shared_secret_client = kem.decap_secret(ciphertext)
                assert shared_secret_server == shared_secret_client
                print("  Functionality Test: PASSED")

                print()
            except Exception as e:
                print(f"  ERROR: {e}")
                print()
        else:
            print(f"Algorithm: {alg} - NOT ENABLED")
            print()

    print()

    # Audit Digital Signature Algorithms
    print("DIGITAL SIGNATURE ALGORITHMS:")
    print("-" * 32)

    sig_algorithms = [
        "Dilithium2",
        "Dilithium3",
        "Dilithium5",
        "Falcon-512",
        "Falcon-1024",
        "Sphincs+-Haraka-128f-robust",
        "Sphincs+-Sha256-128f-robust",
    ]

    for alg in sig_algorithms:
        if alg in oqs.get_enabled_sig_mechanisms():
            try:
                sig = oqs.Signature(alg)
                details = sig.details

                nist_level = get_nist_security_level(alg)

                print(f"Algorithm: {alg}")
                print(f"  NIST Security Level: {nist_level}")
                print(f"  Public Key Length: {details['public_key_length']} bytes")
                print(f"  Secret Key Length: {details['secret_key_length']} bytes")
                print(f"  Signature Length: {details['signature_length']} bytes")
                print(f"  Algorithm Version: {details.get('version', 'N/A')}")

                # Test basic functionality
                pub_key, sec_key = sig.generate_keypair()
                message = b"Audit test message"
                signature = sig.sign(message)
                is_valid = sig.verify(message, signature, pub_key)
                assert is_valid
                print("  Functionality Test: PASSED")

                print()
            except Exception as e:
                print(f"  ERROR: {e}")
                print()
        else:
            print(f"Algorithm: {alg} - NOT ENABLED")
            print()

    print("Audit completed successfully.")
    return 0


def get_nist_security_level(algorithm: str) -> str:
    """
    Return NIST security level for known algorithms.
    Based on NIST PQC selected algorithms.
    """
    nist_levels = {
        # Kyber (Selected)
        "Kyber512": "Level 1",
        "Kyber768": "Level 3",
        "Kyber1024": "Level 5",

        # Dilithium (Selected)
        "Dilithium2": "Level 2",
        "Dilithium3": "Level 3",
        "Dilithium5": "Level 5",

        # Falcon (Selected)
        "Falcon-512": "Level 1",
        "Falcon-1024": "Level 5",

        # FrodoKEM (Alternate)
        "FrodoKEM-640-AES": "Level 1",
        "FrodoKEM-976-AES": "Level 3",
        "FrodoKEM-1344-AES": "Level 5",

        # Sphincs+ (Alternate)
        "Sphincs+-Haraka-128f-robust": "Level 1",
        "Sphincs+-Sha256-128f-robust": "Level 1",
    }

    return nist_levels.get(algorithm, "Unknown")


def run_audit():
    """Entry point for the audit script."""
    try:
        exit_code = main()
        sys.exit(exit_code)
    except Exception as e:
        print(f"Audit failed with error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    run_audit()
