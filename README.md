# QuantumSecureAPI

**Purpose.** Prototype of an API service secured by a hybrid, quantum-aware security stack: Post-Quantum Cryptography (PQC) for authentication + Quantum Key Distribution (QKD) / Quantum Random Number Generator (QRNG) elements where available to derive session symmetric keys (the "QASP" approach).

**Why this project.**
- Protects against harvest-now, decrypt-later attacks and future cryptanalysis.  [oai_citation:2‡0725_military_and_security_dimensions_of_quantum_technologies_0.pdf](sediment://file_00000000c67461f6b084a086ce34ccc0)
- Follows current PQC standardization and transition guidance (NIST, ENISA).  [oai_citation:3‡NIST Computer Security Resource Center](https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization?utm_source=chatgpt.com)
- Provides a reproducible set of docs, ledger and tests for "vibe coding" development.

**Repo layout (created by CLIne)**
- `README.md` (this file)
- `API_SPEC.md` (OpenAPI skeleton + QASP security scheme)
- `docs/SECURITY.md`, `docs/THREAT_MODEL.md`, `docs/QKD_DESIGN.md`, `docs/PQC_PLAN.md`, `docs/FORMAL_VERIFICATION.md`
- `specs/QASP_V0_2.md` (v0.2 specification)
- `vibe_ledger/VIBE_LEDGER.md`
- `specs/IMPLEMENTATION_GUIDE.md`, `specs/OPERATIONAL_RUNBOOK.md`
- `templates/` (issue/PR templates)
- `ci/` (CI job templates)
- `src/` (app skeleton)
- `tests/` (test and adversary/emulation plans)

**Quick start (for developers)**
1. `git init && git checkout -b vibe/init`
2. CLIne will create the files below and commit them as `chore:init-templates`.
3. Read `vibe_ledger/VIBE_LEDGER.md` for tasks and the current sprint.

## Configuring Algorithms

QASP supports crypto-agility through environment variables:

```bash
export KEM_ALG=Kyber512    # Kyber512 (default), Kyber768, Kyber1024, FrodoKEM variants
export SIG_ALG=Dilithium3  # Dilithium3 (default), Dilithium2, Dilithium5, Falcon variants
```

Start with defaults for compatibility. Algorithms are validated at startup.

## Metrics

Prometheus metrics are exposed at `/metrics` endpoint:

- `qasp_handshake_duration_seconds` - Handshake operation latency
- `qasp_handshakes_total` - Total handshakes (success/failure)
- `qasp_challenges_total` - Challenge verification counters
- `qasp_resource_access_total` - Protected resource access counters

## Audit Pipeline

Automated cryptographic audit in CI validates PQC algorithms:

- **Job**: `audit-crypto-params` in GitHub Actions
- **Script**: `tools/audit_crypto_params.py`
- **Output**: `crypto_audit_report.txt` artifact
- **Checks**: Algorithm availability, parameter sizes, NIST levels, functional tests

See `docs/AUDIT_PIPELINE.md` for detailed interpretation guide.

## QASP v0.2 Interoperability Guide

QASP v0.2 introduces multi-tenant isolation, cross-implementation compatibility, and formal verification support.

### Key Features

- **Multi-Tenant Isolation**: Keys and sessions partitioned by `tenant_id`
- **Canonical JSON**: Deterministic message serialization for cross-language interoperability
- **Formal Verification**: Trace logging for TLA+ and ProVerif analysis
- **Client SDK**: Python SDK with interoperability functions

### Migration from v0.1

```bash
# v0.1 clients are compatible with default tenant "default"
# Add tenant_id to requests for v0.2 features
curl -X POST http://localhost:8000/qasp/init \
  -H "Content-Type: application/json" \
  -d '{"client_id":"alice","tenant_id":"tenant1","kem_encaps":"...","client_nonce":"..."}'
```

### Interoperability Testing

Use the client SDK for cross-implementation validation:

```python
from src.interop.qasp_interop import serialize_handshake, validate_message_schema

# Validate message format
message = {"type": "handshake_init", "client_id": "test"}
assert validate_message_schema(message) == False  # Missing version (auto-added)

serialized = serialize_handshake(message)
assert '"qasp_version":"0.2"' in serialized
```

See `specs/QASP_V0_2.md` for complete specification and `docs/FORMAL_VERIFICATION.md` for verification guide.

## Next Steps

Phase 2 (hardening) complete. QASP v0.2 (interop/multitenant/formal-verification) ready for evaluation. Future phases:

1. **Phase 3**: Real hardware integration (HSM, QRNG, QKD)
2. **Phase 4**: Performance optimization and scaling
3. **Phase 5**: Production deployment and monitoring
