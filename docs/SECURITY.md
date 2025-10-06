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

### Mock HSM (Development)
Private PQC keys are stored encrypted at rest using AES-GCM in the database-backed HSM keystore (src/hsm/mock_hsm.py). The master key is derived from the HSM_MASTER_SECRET environment variable. Key operations are logged with INFO and SECURITY levels for audit trails.

- **Key Storage**: Private keys are encrypted with unique nonces and stored persistently in database.
- **Key Retrieval**: On-demand decryption for cryptographic operations.
- **Audit Logging**: All key operations include security event IDs and structured logging.
- **Access Control**: Keys are scoped by tenant_id, client_id and key_type (kem/sign).

### Production KMS Adapters

QASP v1.0 supports production-grade KMS/HSM integrations for enterprise deployments:

#### AWS KMS Adapter (src/hsm/adapters/aws_kms.py)
- **Envelope Encryption**: Uses AWS KMS for data key encryption with AES-256-GCM
- **Key Management**: Data encryption keys (DEKs) generated and managed by KMS
- **Configuration**: Requires AWS_REGION, KMS_KEY_ID, and AWS credentials
- **Security**: Keys never leave AWS infrastructure; all operations logged in CloudTrail
- **Prerequisites**: boto3 library (`pip install boto3`), KMS key with encrypt/decrypt permissions

#### HashiCorp Vault Adapter (src/hsm/adapters/hashicorp_vault.py)
- **Transit Engine**: Uses Vault's transit secrets engine for cryptographic operations
- **Envelope Encryption**: Data keys encrypted using Vault-managed keys
- **Configuration**: Requires VAULT_ADDR, VAULT_TOKEN environment variables
- **Security**: All cryptographic operations performed within Vault; supports key rotation
- **Prerequisites**: hvac library (`pip install hvac`), Vault with transit engine enabled

#### Production Deployment Patterns
1. **HSM Selection**: Choose KMS based on infrastructure (AWS KMS for AWS, Vault for multi-cloud)
2. **Key Rotation**: Configure automatic key rotation policies in KMS/HSM
3. **Access Control**: Use IAM roles/policies (AWS) or Vault policies for fine-grained access
4. **Backup & Recovery**: Ensure KMS key backup procedures are documented
5. **Compliance**: All KMS operations are auditable and meet regulatory requirements

#### Security Considerations for Production
- **Network Security**: Use TLS for all KMS communications
- **Authentication**: Use IAM roles or Vault tokens with minimal required permissions
- **Key Policies**: Implement least-privilege access to KMS keys
- **Monitoring**: Enable CloudTrail (AWS) or audit logs (Vault) for all operations
- **Failover**: Consider multi-region KMS deployments for high availability

## Crypto Agility Policy
QASP supports runtime algorithm selection via environment variables:
- `KEM_ALG`: KEM algorithm (default: Kyber512, alternatives: Kyber768, Kyber1024, FrodoKEM variants)
- `SIG_ALG`: Signature algorithm (default: Dilithium3, alternatives: Dilithium2, Dilithium5, Falcon variants)

Algorithms are validated at startup. Fallback to defaults if unsupported. This enables zero-downtime algorithm upgrades in response to advances in PQC research or security requirements.

## Multi-Tenant Key Isolation (v0.2)

QASP v0.2 implements strict multi-tenant key isolation with the following security controls:

### Key Partitioning
- **HSM Storage**: Keys are stored in tenant-specific namespaces (`tenant_id` prefix)
- **Memory Isolation**: In-memory key stores partitioned by `tenant_id`
- **Access Control**: No cross-tenant key access allowed

### Session Security
- **Token Binding**: Session tokens include encrypted `tenant_id` in payload
- **AEAD Protection**: Associated data ("session-token-{tenant_id}") prevents tenant confusion attacks
- **Isolation Enforcement**: Sessions scoped to tenant namespace

### Audit & Monitoring
- **Tenant Labels**: All metrics and logs include `tenant_id` for per-tenant observability
- **Audit Trails**: Key operations logged with tenant context
- **Compliance**: Multi-tenant operations auditable per tenant

### API Protections
- **Client Partitioning**: Public keys stored per tenant (`_clients[tenant_id][client_id]`)
- **Middleware Verification**: Request signatures verified within tenant scope
- **Endpoint Isolation**: Admin endpoints secured against cross-tenant access

### Threats Mitigated
- **Tenant Confusion**: Explicit tenant ID in all contexts prevents misrouting
- **Key Leakage**: Tenant-scoped HSM prevents cross-tenant key compromise
- **Session Hijacking**: Token binding prevents tenant impersonation
- **Data Exfiltration**: Isolated metrics/logs limit information disclosure

### Implementation Notes
- Default tenant `"default"` maintains backward compatibility with v0.1
- All cryptographic operations include tenant context
- Middleware automatically extracts `tenant_id` from headers or request bodies
- HSM interface extended to require tenant parameter for all operations
