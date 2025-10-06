# Security overview & rationale

This document outlines the security architecture, assumptions and operational guidance
for QuantumSecureAPI.

## High-level strategy
1. **PQC baseline**: Use standardized PQC algorithms for authentication and signatures. NIST has published PQC standards and recommends organizations start the transition now.  [oai_citation:4‡NIST Computer Security Resource Center](https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization?utm_source=chatgpt.com)  
2. **Quantum layer (where available)**: When a QKD link or a QRNG is available between two endpoints, use the QKD/QRNG output as an additional entropy/source to seed session keys — layered with PQC-derived KEM results. SIPRI and other primers recommend layering QKD on top of PQC for high-assurance links.  [oai_citation:5‡0725_military_and_security_dimensions_of_quantum_technologies_0.pdf](sediment://file_00000000c67461f6b084a086ce34ccc0)
3. **Hybrid approach**: All production-grade deployments MUST implement PQC for broad compatibility; QKD is an optional high-value add for selected links (e.g., cross-data-center control plane). ISO/IEC defines baseline requirements and testing for QKD modules.  [oai_citation:6‡ISO](https://www.iso.org/standard/77097.html?utm_source=chatgpt.com)

## Key lifecycle & storage
- Use an enterprise KMS/HSM/TPM to store long-term keys. Do not persist raw QKD outputs without HSM controls.
- Private keys for PQC algorithms (example: Kyber/Dilithium) must be stored only in an HSM or protected keystore.  [oai_citation:7‡NIST Computer Security Resource Center](https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization?utm_source=chatgpt.com)

## Recommended primitives (initial prototype choices)
- KEM / key establishment: **CRYSTALS-Kyber** (example).  [oai_citation:8‡NIST Computer Security Resource Center](https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization?utm_source=chatgpt.com)  
- Digital signatures / authentication: **CRYSTALS-Dilithium** (example).  [oai_citation:9‡NIST Computer Security Resource Center](https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization?utm_source=chatgpt.com)  
- Symmetric cipher & AEAD: AES-GCM or XChaCha20-Poly1305 for application payloads; rotate keys frequently and derive using HKDF over all sources (KEM shared secret || QRNG || QKD key material if present).
- Randomness source: Prefer a certified **QRNG** for seeding high-entropy pools when hardware is available; otherwise use OS CSPRNG seeded by entropy-harvesting best practices.

**Warning:** use vetted libraries (libs that implement FIPS/PQC standards) and hardware HSMs. Do NOT implement crypto primitives yourself.

## Runtime Integration Notes
In production, the implementations in src/qasp/crypto.py will integrate with HSM/KMS for private key operations. The TODO comments in the code indicate where HSM calls should plug in (e.g., `store_priv_kem_in_hsm()` or `hs_m_kem_encapsulate()`). For QKD, replace the mock service in src/qkd/mock_qkd.py with actual hardware providers exposing REST APIs or direct hardware interfaces. Ensure QKD keys are handled only in volatile memory and never logged in plaintext.

## HSM Integration & Operational Security Controls
Private PQC keys are stored encrypted at rest using AES-GCM in the HSM keystore (src/hsm/mock_hsm.py). The master key is derived from the HSM_MASTER_SECRET environment variable. Key operations are logged with INFO and SECURITY levels for audit trails.

- **Key Storage**: Private keys are encrypted with unique nonces and stored in memory.
- **Key Retrieval**: On-demand decryption for cryptographic operations.
- **Audit Logging**: All key operations include security event IDs and structured logging.
- **Access Control**: Keys are scoped by client_id and key_type (kem/sign).

## Crypto Agility Policy
QASP supports runtime algorithm selection via environment variables:
- `KEM_ALG`: KEM algorithm (default: Kyber512, alternatives: Kyber768, Kyber1024, FrodoKEM variants)
- `SIG_ALG`: Signature algorithm (default: Dilithium3, alternatives: Dilithium2, Dilithium5, Falcon variants)

Algorithms are validated at startup. Fallback to defaults if unsupported. This enables zero-downtime algorithm upgrades in response to advances in PQC research or security requirements.
