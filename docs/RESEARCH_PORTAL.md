# QASP Research Collaboration Portal

## Overview
The QASP Research Collaboration Portal enables secure, trustless data-sharing between research partners, academia, and industry stakeholders for QASP v2.0 interoperability studies and quantum-network research.

## Data-Sharing Protocol
- **Participants**: Any entity with a verifiable PQC DID can contribute metrics.
- **Data Types**:
  - QKD interoperability metrics (key exchange latency, failure rates)
  - PQC algorithm performance under threat simulations
  - Multi-vendor QKD mesh topology utilization
- **Submission**: Via POST /research/submit with signed payload.
- **Attestation**: Cryptographic proof of data authenticity using Dilithium signatures.

## Submission Format
```json
{
  "researcher_did": "did:qasp:researcher123",
  "timestamp": 1730928963,
  "metrics": {
    "qkd_vendor": "Huawei",
    "kyber_adoption": 0.75,
    "latency_ms": 12,
    "failover_events": 2
  },
  "signature": "dilithium_signature_b64"
}
```

## Attestation Mechanism
1. Researcher signs metrics with their Dilithium private key.
2. Portal verifies signature against the public key resolved from DID.
3. Data is stored with attestation metadata for reproducibility.
4. Aggregated anonymized data shared back via the portal.

## Endpoints
- **GET /research/data**: Filtered authenticated download of aggregated research data.
- **POST /research/submit**: Submit new metrics (requires DID authentication).
- **GET /research/did/{did}**: Resolve research partner DID public keys.

## Governance
- All submissions undergo automated integrity checks.
- Sensitive data is anonymized before aggregation.
- Privacy-preserving techniques applied per ENISA guidelines.
- Sponsored by SIPRI for cross-border quantum governance compliance.

References: ISO/IEC 23837-3, W3C DID, NIST SP 800-185 (SHA-3 destruction)
