# QASP v1.0 Compliance Guide

This guide outlines QASP v1.0 compliance with international standards for post-quantum cryptography, quantum key distribution, and security certification.

## NIST PQC Migration Framework Alignment

QASP v1.0 implements NIST-selected post-quantum cryptographic algorithms in accordance with [NIST SP 800-208](https://csrc.nist.gov/pubs/sp/800/208/final) and the broader PQC migration framework.

### Supported Algorithms

#### Key Encapsulation Mechanisms (KEM)
- Kyber512 (NIST Round 3 finalist, security level 1)
- Kyber768 (NIST Round 3 finalist, security level 3)
- Kyber1024 (NIST Round 3 finalist, security level 5)

#### Digital Signatures
- Dilithium2 (NIST Round 3 finalist, security level 2)
- Dilithium3 (NIST Round 3 finalist, security level 3)
- Dilithium5 (NIST Round 3 finalist, security level 5)

### Algorithm Selection Guidelines

1. **Security Level 2**: Suitable for applications requiring ~128-bit classical security
   - Recommended: Kyber512 + Dilithium2

2. **Security Level 3**: Suitable for applications requiring ~192-bit classical security
   - Recommended: Kyber768 + Dilithium3

3. **Security Level 5**: Suitable for applications requiring maximum quantum security
   - Recommended: Kyber1024 + Dilithium5

### Configuration

Algorithms are configured via environment variables or configuration files:

```bash
# Set PQC algorithms
export PQC_KEM_ALGORITHM=Kyber768
export PQC_SIGNATURE_ALGORITHM=Dilithium3

# Enable HSM integration for key protection
export HSM_ENABLED=true
```

## ISO/IEC 23837 QKD Baseline Compliance

QASP v1.0 incorporates quantum key distribution compliant with [ISO/IEC 23837](https://www.iso.org/standard/82680.html) standards for QKD system security evaluation.

### QKD Security Claims

- **Key Material Security**: QKD keys provide information-theoretic security
- **Device Authentication**: Hardware drivers implement vendor certificate validation
- **Key Freshness**: Keys are used within bounded time windows
- **Side-Channel Protection**: Timing and power analysis mitigations

### Hardware Integration

#### Simulated Mode
For development and testing, QASP provides a simulated QKD driver that generates test keys with proper metadata tracking.

#### Hardware Mode
Production deployments integrate with certified QKD hardware:
- ID Quantique Cerberis systems
- Toshiba QKD Link systems
- Other ISO 23837-compliant devices

### Configuration Example

```bash
# Enable QKD hardware integration
export QKD_HARDWARE_ENABLED=true
export QKD_MODE=hardware

# Vendor-specific configuration
export QKD_VENDOR=id_quantique
export QKD_DEVICE_ID=cerberis-001
```

## FIPS 140-3 Alignment

QASP v1.0 includes provisions for FIPS 140-3 compliance in cryptographic module design.

### Key Protection Mechanisms

#### Hardware Security Modules (HSM)
- Integration with FIPS 140-3 Level 3+ HSMs
- Key generation in hardware security boundary
- Encrypted key storage with access controls

#### QKD Key Handling
- QKD-derived keys treated as high-value assets
- Automatic rotation based on usage and time limits
- Secure key deletion on compromise

### FIPS Mode Configuration

```bash
# Enable FIPS-compliant modes
export TLS_FIPS_MODE=true
export HSM_FIPS_MODE=true
export CRYPTO_FIPS_MODE=true
```

### FIPS Validation Status

| Component | FIPS Level | Status | Notes |
|-----------|------------|--------|-------|
| Kyber KEM | N/A | Ready | PQ algorithm, no FIPS yet |
| Dilithium | N/A | Ready | PQ algorithm, no FIPS yet |
| AES-GCM | 140-3 | Pending | OpenSSL FIPS module |
| SHA-3 | 140-3 | Pending | OpenSSL FIPS module |
| QKD Hardware | 140-3 | Vendor Dependent | Hardware certification required |

## Logging and Traceability for Auditors

QASP v1.0 implements comprehensive audit logging compliant with ISO 27001 and NIST guidelines.

### Audit Event Types

#### Security Events
- Authentication success/failure
- Authorization decisions
- Key lifecycle events (generation, usage, destruction)
- QKD hardware status changes
- Cryptographic operation failures

#### Operational Events
- System startup/shutdown
- Configuration changes
- Performance metrics
- Error conditions

### Log Structure

All logs use structured JSON format with the following fields:

```json
{
  "timestamp": "2025-10-06T11:30:00.000Z",
  "level": "info|warning|error",
  "service": "qasp-server",
  "event_id": "handshake_success",
  "client_id": "client-123",
  "session_id": "session-456",
  "tenant_id": "tenant-789",
  "qkd_used": true,
  "device_id": "qkd-device-001",
  "additional_context": {}
}
```

### Audit Log Integrity

- Logs are written to tamper-evident storage
- Cryptographic signatures on log entries (optional)
- Log rotation with integrity verification
- Secure transport to SIEM systems

### Retention Policy

- Security events: 7 years minimum
- Operational logs: 1 year minimum
- Archive to immutable storage after retention period

### Log Analysis Tools

QASP provides tools for audit log analysis:

```bash
# Generate compliance report from logs
python tools/audit_log_analyzer.py --start-date 2025-01-01 --end-date 2025-12-31

# Check log integrity
python tools/log_integrity_checker.py logs/*.json
```

## Compliance Verification

### Automated Checks

Run the compliance audit pipeline:

```bash
python audit_pipeline/generate_audit_report.py
```

This generates `audit_pipeline/reports/audit_report_v1_0.json` with automated compliance status for:
- Algorithm configuration validation
- Hardware driver integrity
- Key storage security
- QKD failover mechanisms

### Manual Verification Steps

1. **Certificate Review**: Validate all certificates in the trust chain
2. **Configuration Audit**: Review all environment variables and config files
3. **Key Management Review**: Verify key lifecycle policies and procedures
4. **Network Security**: Assess firewall configurations and access controls
5. **Physical Security**: Review hardware deployment and access controls

### External Validation

For formal certification, engage accredited laboratories:
- FIPS 140-3 validation: NIST accredited labs
- ISO/IEC 23837 QKD certification: National metrology institutes
- Common Criteria EAL evaluation: Certified evaluation facilities

## Migration Path from Legacy Systems

### Hybrid Mode Operation

QASP supports hybrid classical/PQC modes during migration:

```bash
# Enable hybrid mode
export CRYPTO_HYBRID_MODE=true

# Fall back to RSA/ECDSA if PQC fails
export CRYPTO_FALLBACK_ENABLED=true
```

### Interoperability

QASP client SDKs support multiple protocol versions:
- QASP v0.2 (legacy compatibility)
- QASP v1.0 (PQC + QKD)
- Hybrid handshake modes

## References

- NIST PQC Migration Framework: https://csrc.nist.gov/Projects/post-quantum-cryptography
- ISO/IEC 23837 QKD Security: https://www.iso.org/standard/82680.html
- FIPS 140-3 Documentation: https://csrc.nist.gov/pubs/fips/140-3/final
- ENISA PQC Guidelines: https://www.enisa.europa.eu/publications/post-quantum-cryptography
