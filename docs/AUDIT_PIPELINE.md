"""
# QASP Cryptographic Audit Pipeline

This document describes the automated cryptographic audit pipeline implemented in QASP Phase 2,
which validates PQC algorithm parameters, functionality, and compliance in CI/CD.

## Overview

The audit pipeline consists of:
1. **CI Job**: `audit-crypto-params` in `.github/workflows/ci.yml`
2. **Audit Script**: `tools/audit_crypto_params.py`
3. **Output**: `crypto_audit_report.txt` uploaded as GitHub artifact

## CI Job Details

### Trigger
- Runs on pushes to `main`, `vibe/dev/initial-implementation`
- Runs on PRs to `main`
- Must pass before merging to `main`

### Dependencies
- Ubuntu latest
- Python 3.11
- Build tools (cmake, gcc, make, libssl-dev)
- Dependencies from `requirements.txt`

### Execution Steps
1. Install build dependencies
2. Install Python dependencies (including oqs-python)
3. Run audit script: `python tools/audit_crypto_params.py > crypto_audit_report.txt`
4. Upload artifact

## Audit Script Functionality

### Algorithms Tested
- **KEM (Key Encapsulation Mechanisms)**:
  - Kyber512, Kyber768, Kyber1024
  - FrodoKEM-640-AES, FrodoKEM-976-AES, FrodoKEM-1344-AES

- **Digital Signatures**:
  - Dilithium2, Dilithium3, Dilithium5
  - Falcon-512, Falcon-1024
  - Sphincs+-Haraka-128f-robust, Sphincs+-Sha256-128f-robust

### Validation Performed
For each algorithm:
1. **Availability Check**: Verify algorithm is enabled in OQS library
2. **Parameter Extraction**:
   - NIST Security Level
   - Key lengths (public, private, ciphertext, shared secret, signature)
   - Algorithm version
3. **Functional Testing**:
   - Generate keypair
   - Test encapsulation/decapsulation (KEM) or sign/verify (signature)
   - Validate shared secrets or signatures match

### Error Handling
- Reports "NOT ENABLED" for unavailable algorithms
- Shows specific errors for functional failures
- Exits with non-zero code on critical failures

## Output Format

### Report Structure
```
QASP Cryptographic Parameters Audit
==================================================
Report generated: 2025-10-06T15:30:00Z
Open Quantum Safe (OQS) version: 0.8.0
Python OQS version: 0.8.0

KEY ENCAPSULATION MECHANISMS (KEM):
----------------------------------
Algorithm: Kyber512
  NIST Security Level: Level 1
  Public Key Length: 800 bytes
  Secret Key Length: 1632 bytes
  Ciphertext Length: 768 bytes
  Shared Secret Length: 32 bytes
  Algorithm Version: N/A
  Functionality Test: PASSED
```

### Key Metrics

#### NIST Security Levels
- **Level 1**: 128-bit security equivalent
- **Level 2**: 192-bit security equivalent (Dilithium2)
- **Level 3**: 256-bit security equivalent (Kyber768, Dilithium3)
- **Level 5**: >256-bit security (Kyber1024, Dilithium5, Falcon-1024)

#### Key Sizes
- Typical KEM public keys: 800-1568 bytes
- Typical signature public keys: 1312-2592 bytes
- Ciphertexts: 736-1568 bytes
- Signatures: 2420-4595 bytes

## Interpretation Guide

### Successful Audit
- All enabled algorithms pass functionality tests
- Parameter sizes match expectations for NIST levels
- No "ERROR" entries in report

### Common Issues
- **NOT ENABLED**: Algorithm not compiled in OQS (check build flags)
- **Functionality Test: FAILED**: Potential library issue or host problem
- **Parameter Mismatches**: May indicate incompatible library version

### Performance Considerations
- KEM operations: Fast (microseconds)
- Signature generation/verification: Slower (milliseconds)
- Memory usage: Algorithm-dependent (1-3KB per keypair)

## Integration Points

### QASP Configuration
Audit validates algorithms configured via:
- `KEM_ALG`: Must be in supported KEM list
- `SIG_ALG`: Must be in supported signature list

### Monitoring
Results feed into:
- CI/CD gates
- Security dashboards
- Compliance reports

## Future Enhancements

1. **Extended Testing**:
   - Performance benchmarks
   - Memory usage analysis
   - Side-channel resistance checks

2. **Compliance Integration**:
   - FIPS validation
   - ISO standards checking
   - Regulatory reporting

3. **Automated Alerts**:
   - Slack/Discord notifications on failures
   - Dashboard integration
   - Trend analysis over time
"""
