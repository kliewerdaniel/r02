# API_SPEC (security excerpt) — OpenAPI / conceptual

## Overview
This file contains a security scheme description for the experimental **QASP** (Quantum API Security Protocol) and an OpenAPI securityScheme snippet for integration.

## QASP handshake (conceptual sequence)
- Notation:
  - `Client` and `Server`.
  - `KEM(pub,priv)` = PQC KEM pair (e.g., Kyber).
  - `SIGN` = PQC signature (e.g., Dilithium).
  - `QKD_KEY_ID` = identifier of a QKD session key if available.

### 1) Client Registration
- Client registers `pub_kem` and `pub_sign` with server via out-of-band provisioning (or DOS-protected API). The registration is signed or provisioned via HSM attestation.

### 2) Session initiation (client -> server)

POST /qasp/init
Body:
{
"client_id": "acme-client-42",
"kem_encaps": "",
"supported_qkd": true/false,
"nonce": "<client_nonce>"
}

Server decapsulates `kem_encaps` with its `priv_kem` -> `shared_secret_kem`.
If QKD available and accepted, server returns `QKD_KEY_ID` and ephemeral server nonce.

### 3) Key derivation
Client and server derive session AEAD key:
`session_key = HKDF(shared_secret_kem || qkd_key(if present) || QRNG_output(if present) || client_nonce || server_nonce)`

### 4) Challenge / Verify
Server sends challenge MAC'd with `session_key`. Client responds with MAC and signs a transcript with its `priv_sign` (optional high-assurance step), server verifies.

**Security notes:**
- Signatures provide non-repudiation for client provisioning events.
- Ephemeral KEM per session gives forward secrecy; combining QKD/QRNG adds hardware-rooted entropy where available.
- All endpoints MUST accept PQC-signed registration and fallback to PQC KEM handshake if QKD is not available.

## OpenAPI securitySchemes (conceptual snippet)
```yaml
components:
  securitySchemes:
    QASP:
      type: apiKey
      in: header
      name: X-QASP-Session
      description: >
        Short opaque session token proving possession of a QASP-derived session key.
        Token is issued after a successful QASP handshake and is MAC'd with AEAD using session_key.
security:
 - QASP: []
