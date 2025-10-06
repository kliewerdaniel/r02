# QASP Protocol Specification v1.0

## Overview

The QuantumSecureAPI Protocol (QASP) v1.0 provides quantum-resistant authentication and session establishment for API communications. This specification defines the protocol messages, cryptographic operations, and security guarantees for cross-language interoperability.

## Core Features

- **Post-Quantum Cryptography**: Built on NIST-standardized PQC algorithms
- **Multi-Tenant Support**: Isolated key management and sessions per tenant
- **Cross-Language Compatibility**: Canonical JSON serialization for consistent message handling
- **Production KMS Integration**: Pluggable HSM/KMS backends (AWS KMS, HashiCorp Vault, etc.)
- **Audit & Compliance**: Comprehensive security event logging

## Protocol Architecture

### Handshake Flow

```
Client                  Server
  │                       │
  ├─ HandshakeInit ─────►│
  │                       │
  │◄─ HandshakeChallenge ─┤
  │                       │
  ├─ HandshakeComplete ─►│
  │                       │
  │◄─ SessionEstablished ─┤
  │                       │
  ├─ AuthenticatedRequest─┤
  │◄─ ProtectedResponse ──┤
```

### Message Format

All QASP messages use canonical JSON with the following structure:

```json
{
  "qasp_version": "v1.0",
  "type": "<message_type>",
  "client_id": "<client_identifier>",
  "tenant_id": "<tenant_identifier>",
  "timestamp": <unix_timestamp_ms>,
  "nonce": "<unique_nonce>",
  ...additional_fields
}
```

## Message Types

### HandshakeInit

Initiates the QASP handshake.

**Fields:**
- `qasp_version`: "v1.0"
- `type`: "handshake_init"
- `client_id`: Unique client identifier
- `tenant_id`: Tenant identifier (default: "default")
- `kem_alg`: KEM algorithm (e.g., "Kyber512")
- `sig_alg`: Signature algorithm (e.g., "Dilithium3")
- `timestamp`: Current timestamp (milliseconds)
- `client_nonce`: Base64-encoded random nonce

### HandshakeChallenge

Server response with authentication challenge.

**Fields:**
- `qasp_version`: "v1.0"
- `type`: "handshake_challenge"
- `session_id`: Unique session identifier
- `server_public_key`: Base64-encoded server public key
- `server_signature`: Base64-encoded server signature
- `challenge`: Authentication challenge data

### HandshakeComplete

Client completion of handshake.

**Fields:**
- `qasp_version`: "v1.0"
- `type`: "handshake_complete"
- `client_id`: Unique client identifier
- `tenant_id`: Tenant identifier
- `session_id`: Session identifier from challenge
- `client_public_key`: Base64-encoded client public key
- `client_signature`: Base64-encoded client signature
- `timestamp`: Current timestamp (milliseconds)

### SessionEstablished

Server confirmation of established session.

**Fields:**
- `qasp_version`: "v1.0"
- `type`: "session_established"
- `session_token`: Opaque session token
- `expires_at`: Session expiration timestamp

## Cryptographic Algorithms

### Supported KEM Algorithms

| Algorithm | NIST Level | Key Size | Status |
|-----------|------------|----------|--------|
| Kyber512 | 1 | 512-bit security | 🟢 Supported |
| Kyber768 | 3 | 768-bit security | 🟢 Supported |
| Kyber1024 | 5 | 1024-bit security | 🟢 Supported |

### Supported Signature Algorithms

| Algorithm | NIST Level | Key Size | Status |
|-----------|------------|----------|--------|
| Dilithium2 | 2 | 128-bit security | 🟢 Supported |
| Dilithium3 | 3 | 192-bit security | 🟢 Supported |
| Dilithium5 | 5 | 256-bit security | 🟢 Supported |

## Security Properties

### Confidentiality
- All key material is encrypted at rest using AES-256-GCM
- Session keys are derived using HKDF over authenticated inputs
- TLS 1.3 required for all network communications

### Integrity
- All messages include cryptographic signatures
- HMAC-SHA256 request authentication for API calls
- Nonce-based replay attack prevention

### Availability
- Stateless session tokens with configurable expiration
- Rate limiting on handshake endpoints
- Automatic key rotation capabilities

### Multi-Tenant Isolation
- Tenant-scoped key storage and retrieval
- Isolated session namespaces per tenant
- Per-tenant audit logging and monitoring

## SDK Implementations

### Supported Languages

1. **Python** (`sdk/python/`)
   - Native liboqs-python integration
   - FastAPI-compatible session handling
   - Comprehensive error handling

2. **JavaScript/Node.js** (`sdk/js/`)
   - npm-compatible package structure
   - Promise-based async operations
   - Compatible with browser and server environments

3. **Go** (`sdk/go/`)
   - goroutine-safe session management
   - Context-aware timeout handling
   - Standard library HTTP client integration

### Canonical JSON Implementation

All SDKs implement RFC 8785 compliant canonical JSON serialization:

```javascript
// JavaScript example
function canonicalize(obj) {
  return JSON.stringify(obj, Object.keys(obj).sort(), 0);
}
```

```go
// Go example
func canonicalJSONMarshal(v interface{}) ([]byte, error) {
  // Sort keys and minimize whitespace
  return json.Marshal(v) // with canonical formatting
}
```

## Error Codes

### Handshake Errors

| Code | Description | HTTP Status |
|------|-------------|-------------|
| `INVALID_VERSION` | Unsupported QASP version | 400 |
| `INVALID_ALGORITHM` | Unsupported cryptographic algorithm | 400 |
| `TENANT_NOT_FOUND` | Specified tenant does not exist | 403 |
| `CLIENT_QUOTA_EXCEEDED` | Client has exceeded rate limits | 429 |

### Authentication Errors

| Code | Description | HTTP Status |
|------|-------------|-------------|
| `INVALID_TOKEN` | Session token is invalid or expired | 401 |
| `INVALID_SIGNATURE` | Request signature verification failed | 401 |
| `REPLAY_ATTACK` | Request is a replay attack | 401 |

## Deployment Considerations

### Infrastructure Requirements

- **Database**: PostgreSQL 15+ or SQLite (development)
- **HSM/KMS**: HSM, AWS KMS, or HashiCorp Vault
- **Monitoring**: Prometheus metrics endpoint
- **Load Balancing**: Stateless session design supports horizontal scaling

### Environment Variables

```bash
# Database
DATABASE_URL=postgresql://qasp:password@localhost/qasp

# Cryptographic Configuration
KEM_ALG=Kyber512
SIG_ALG=Dilithium3

# KMS Configuration (example for AWS KMS)
HSM_TYPE=aws_kms
AWS_REGION=us-east-1
KMS_KEY_ID=arn:aws:kms:us-east-1:123456789:key/your-key-id

# Security
RATE_LIMIT_REQUESTS=10
RATE_LIMIT_PERIOD=60
```

## Interoperability Testing

QASP v1.0 maintains interoperability across implementations through:

1. **Golden File Testing**: Canonical message serialization validation
2. **Cross-SDK Handshake**: Multi-language client compatibility testing
3. **Protocol Conformance**: Automated verification of message formats

### Testing Strategy

```bash
# Run interoperability tests
make test-interop

# Validate with all SDKs
node examples/sdk_demo_js.js
go run examples/sdk_demo_go.go
python examples/sdk_demo.py
```

## Future Extensions

### Planned Features (v1.1+)

- **QKD Integration**: Quantum Key Distribution support
- **Federated Authentication**: Cross-domain session establishment
- **Hardware Token Support**: FIDO2/WebAuthn integration
- **Advanced KMS Providers**: Additional cloud KMS integrations

### Protocol Extensions

- **Version Negotiation**: Support for multiple protocol versions
- **Extension Fields**: Extensible message format for custom fields
- **Compression**: Optional message compression for bandwidth optimization

## Reference Implementation

The reference implementation (`src/`) includes:

- **Server**: FastAPI-based implementation with full protocol support
- **HSM Abstraction**: Pluggable KMS integration layer
- **Database Models**: SQLAlchemy-based persistent storage
- **Monitoring**: Prometheus metrics and structured logging

## Security Audit

This specification and implementation have been designed with security as a primary concern. Regular security audits, dependency updates, and formal verification are recommended for production deployments.
