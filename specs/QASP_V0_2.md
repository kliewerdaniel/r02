# QASP v0.2 Specification

## Overview

QASP v0.2 extends v0.1 with multi-tenant key isolation, cross-implementation interoperability, and formal verification hooks.

## Protocol Versioning

All QASP messages include a `qasp_version` field set to `"0.2"`.

## Message Format

Messages use canonical JSON serialization:
- Keys sorted alphabetically (standard JSON sort)
- No whitespace (minified)
- UTF-8 encoding

### Serialize/Deserialize Functions

```python
def serialize_handshake(message: Dict[str, Any]) -> str:
    # Ensures qasp_version: "0.2" and validation

def deserialize_handshake(json_str: str) -> Dict[str, Any]:
    # Validates version and structure
```

## Message Types

### Handshake Initialization

```json
{
  "qasp_version": "0.2",
  "type": "handshake_init",
  "client_id": "client-123",
  "tenant_id": "tenant-ABC",
  "kem_encaps": "<base64>",
  "client_nonce": "<base64>",
  "supported_qkd": false
}
```

### Handshake Response

```json
{
  "qasp_version": "0.2",
  "type": "handshake_response",
  "server_nonce": "<base64>",
  "session_token": "<base64>"
}
```

### Challenge Request

```json
{
  "qasp_version": "0.2",
  "type": "challenge_request",
  "challenge_nonce": "<base64>",
  "challenge_ciphertext": "<base64>"
}
```

### Challenge Response

```json
{
  "qasp_version": "0.2",
  "type": "challenge_response",
  "challenge_verified": true
}
```

### Resource Response

```json
{
  "qasp_version": "0.2",
  "type": "resource_response",
  "nonce": "<base64>",
  "ciphertext": "<base64>"
}
```

## Multi-Tenant Architecture

- Keys are partitioned by `tenant_id`
- Session tokens include `tenant_id` in payload and AAD
- Metrics labeled with `tenant_id`
- Clients and sessions isolated by tenant namespace

## Cryptographic Algorithms

### Key Encapsulation Mechanisms (KEM)
- Kyber512
- Kyber768
- Kyber1024

### Digital Signatures
- Dilithium2
- Dilithium3
- Dilithium5

### Symmetric Encryption
- AES-GCM (256-bit)
- ChaCha20-Poly1305

## Formal Verification Hooks

### Trace Logging

Protocol events logged to `logs/trace_log.json`:

```json
[
  {
    "timestamp": "2025-10-06T11:15:00.000Z",
    "event_type": "handshake_init",
    "qasp_version": "0.2",
    "payload": {
      "session_id": "session-123",
      "tenant_id": "tenant-A",
      "client_id": "client-X",
      "state": "handshake_initialization"
    }
  }
]
```

### State Model

Handshake states: INIT → CHALLENGE → ESTABLISHED

```python
STATES = {
    "INIT": "handshake_initialization",
    "CHALLENGE": "challenge_verification",
    "ESTABLISHED": "session_established"
}
```

## API Changes

### New Fields

- All handshake messages: `tenant_id`, `qasp_version`
- Session tokens: include `tenant_id` in encrypted payload
- AEAD additional data: binds `tenant_id`

### New Endpoints

- `POST /qasp/register`: accepts `tenant_id` in body
- `GET /admin/tenants`: lists tenant IDs

### Metrics Labels

- `qasp_handshakes_total`: `{result, tenant_id}`
- `qasp_challenges_total`: `{result, tenant_id}`
- `qasp_resource_access_total`: `{result, tenant_id}`

## Compatibility

- Backward compatible with v0.1 clients (default tenant: "default")
- Message format changes are additive
- HSM interface extended with tenant context

## Error Codes

- `400`: Missing required fields, invalid base64
- `401`: Invalid client, failed verification
- `404`: Client not registered
- `500`: Internal server errors (logged)
