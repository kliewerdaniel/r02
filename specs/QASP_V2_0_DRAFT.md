# QASP v2.0 Architecture Draft

## Overview
QASP v2.1 introduces adaptive cryptography, multi-vendor quantum-network interoperability, and AI-driven threat intelligence to enhance security agility and scale.

## Key Innovations

### 1. Adaptive Cryptography Loop
- **Concept**: LLM-driven policy engine recommends algorithm rotation based on real-time threat metrics from NIST bulletins, PQC risk assessments, and continuous latency measurements.
- **Mechanism**:
  - Aggregate threat-intelligence feeds (JSON format from `/threat_feeds/`).
  - Simulate algorithm performance against threat models.
  - Recommend migration: e.g., from Kyber768 to ML-KEM-1024 on rising decryption failure rates.
- **Safety Guards**: Human oversight required for rotations; automated audits log all recommendations and rationale.
- **Benefits**: Proactive risk mitigation without manual intervention.

### 2. Multi-Vendor QKD Mesh Topology
- **Concept**: Support simultaneous integration of multiple QKD providers (e.g., Huawei QKD, Quantum Xchange Phio) in a mesh network for redundancy and scale.
- **Architecture**:
  - Trust overlay: Decentralized DID-based identity federation.
  - Mesh key distribution: Simultaneous key exchange across vendors via plug-ins.
  - Failover: Automatic switch to alternative QKD providers on hardware failures or locality mismatches.
- **Provider Registry**: Vendor-agnostic driver interfaces; hot-swappable for new entrants.

### 3. Cross-Domain Identity Federation
- **Credentials**: PQC-based certificates (Dilithium-Sig) + DIDs (following W3C DID standard) for trustless identity resolution.
- **Federation Flow**:
  1. Issue DID by QASP HSM.
  2. Resolve identities across domains (e.g., enterprise QKD sites).
  3. Zero-knowledge proofs for credential verification without revealing private keys.
- **Compliance**: Aligns with SIGMA for quantum-resistant authentication.

### 4. Dynamic Session-Key Renegotiation
- **Triggering**: Automated renegotiation on threat-intel events (e.g., PQC algorithm compromise detected).
- **Process**:
  - Interrupt active sessions.
  - Renegotiate key pairs using updated algorithms.
  - Log and alert for session continuity assurance.

## Research Timelines
- Q1 2026: Prototype adaptive loop with mock LLM.
- Q2 2026: Multi-vendor QKD slits integration.
- Q3 2026: Cross-domain federation pilot.
- Q4 2026: v2.0 alpha release.

## Diagrams

### QASP v2.0 Control-Plane Flow
```
[Client Request] -> [Identity Resolver (DID)] -> [QKD Mesh Distributor] -> [Adaptive Crypto Engine] -> [Session Setup]
                     |                           |                               |
               Validate Credentials        Route to Optimal Vendor      Recommend Algorithm Shift
```

### Quantum Network Mesh and Trust Overlay
```
           +-------------------+     +-------------------+
           | QKD Vendor A      |     | QKD Vendor B      |
           | (Huawei)          |-----| (QX Phio)         |
           +-------------------+     +-------------------+
                   |                           |
                   | Trusted DID Exchange      |
                   +---------------------------+
                               |
                  +-------------------+
                  | Trust Overlay     |
                  | (DIDs + PQC Certs)|
                  +-------------------+
                               |
                  +-------------------+
                  | QASP Control Plane|
                  +-------------------+
```

References: NIST PQC, ISO/IEC 23837-3, ENISA 2025 Quantum-Network Report, SIPRI Governance Primer.
