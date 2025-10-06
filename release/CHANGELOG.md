# QASP Changelog

All notable changes to QASP will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-10-14 - Stable Release

QASP v1.0 represents the first stable, production-ready release of the Quantum-Secure Authentication Protocol. This release introduces quantum key distribution hardware integration, comprehensive auditing and compliance frameworks, and automated failover mechanisms.

### Added
- **Quantum Hardware Integration**
  - `src/qkd/hardware_driver.py`: Abstract QKD driver interface with simulated and hardware implementations
  - Server startup detection for `QKD_HARDWARE_ENABLED` environment variable
  - `/hardware/status` endpoint for QKD hardware monitoring
  - Support for ID Quantique Cerberis and Toshiba QKD Link systems

- **External Audit & Compliance Pipeline**
  - `audit_pipeline/audit_checklist.yaml`: Compliance controls map for ISO/IEC 23837, NIST SP 800-208, ENISA PQC
  - `audit_pipeline/generate_audit_report.py`: Automated compliance checking and report generation
  - CI job `external-audit` with weekly execution and artifact publishing
  - Reports output to `audit_pipeline/reports/audit_report_v1_0.json`

- **Compliance Documentation**
  - `docs/COMPLIANCE_GUIDE.md`: NIST PQC migration alignment, ISO/IEC 23837 QKD compliance, FIPS 140-3 guidance
  - `docs/CERTIFICATION_PREP.md`: FIPS 140-3, ISO/IEC 23837, Common Criteria EAL certification preparation guide

- **Resilience & Failover Mechanisms**
  - `src/resilience/failover.py`: Automatic QKD hardware failover to PQC-only mode
  - Health monitoring with configurable thresholds and alerting
  - Prometheus alert rules for QKD failures in `infra/monitoring/prometheus_rules.yml`
  - QKD metrics integration in `src/telemetry/metrics.py`

- **Extended Performance Testing**
  - `tools/perf_stress_qasp.py`: Async stress testing tool for 1000+ concurrent handshakes
  - Performance reports in `reports/perf_v1_0_stable.json`
  - Grafana-ready metrics export for visualization
  - CI job `stress-test` with performance threshold validation

- **Release Automation**
  - Release tooling and automation scripts
  - SBOM (Software Bill of Materials) generation using CycloneDX
  - Signed Git tag creation for v1.0-stable

### Security
- QKD hardware failure automatic fallback with logging
- Comprehensive audit logging with traceability
- FIPS 140-3 compliance provisions
- Hardware security module integration

### Performance
- Average handshake latency ≤ 500ms target
- Stress testing validation for 1000+ concurrent handshakes
- Error rate monitoring < 0.5%
- QKD latency monitoring and alerting

### Compliance
- ISO/IEC 23837 QKD baseline compliance
- NIST SP 800-208 PQC migration alignment
- ENISA PQC transition recommendations
- Automated compliance auditing

## [0.2.0] - 2025-10-10 - Multi-Tenant & Interoperability

### Added
- Multi-tenant key isolation with tenant-scoped HSM storage
- Cross-implementation interoperability with canonical JSON serialization
- Formal verification hooks with TLA+/ProVerif-ready trace logging
- Python SDK for client-side protocol implementation
- Conformance tests with golden file validation
- Session token binding to tenant_id
- Tenant-labeled Prometheus metrics

### Technical Details
- **Ledger Entry 0005**: Design QASP v0.2 interoperability & multi-tenant model
- **Ledger Entry 0006**: Implement v0.2 handshake, SDK, and formal verification hooks

## [0.1.0] - 2025-10-06 - Initial Implementation

### Added
- Core QASP v0.1 protocol implementation with PQC + QKD-inspired session keys
- HSM/KMS abstraction layer with MockHSM for key storage
- Post-quantum cryptographic algorithms (Kyber KEM + Dilithium signatures)
- FastAPI-based server with rate limiting and security middleware
- Structured logging with JSON output and Prometheus metrics
- CI/CD pipeline with PQC compatibility testing
- Documentation and threat modeling

### Technical Details
- **Ledger Entry 0001**: Create initial repo templates
- **Ledger Entry 0002**: Initial dev implementation
- **Ledger Entry 0003**: Design HSM/KMS abstraction + telemetry
- **Ledger Entry 0004**: Implement crypto-agility config, audit pipeline, rate-limiting

---

## Ledger Summary

**Total Entries**: 10
**Date Range**: 2025-10-06 to 2025-10-16
**Major Themes**:
- Progressive implementation from design to stable release
- Security hardening through multiple phases
- Compliance and audit trail establishment
- Performance validation and monitoring
- Quantum hardware integration and failover resilience

### Key Decisions
- Hybrid PQC + QKD pattern for forward compatibility
- HSM-based key storage for production security
- NIST-selected algorithms (Kyber, Dilithium)
- Automated compliance and audit tooling
- Failover mechanisms for quantum hardware availability
- Multi-tenant architecture for enterprise deployment

### Quality Assurance
- Formal verification hooks and trace logging
- Automated security auditing and compliance checks
- Performance stress testing with acceptance criteria
- Comprehensive documentation for certification
- Signed releases with SBOM for supply chain security

---

## Release Notes

### v1.0.0-stable (2025-10-16)
**Tag**: `v1.0-stable`
**Commit**: [TBD]
**SBOM**: Available at `release/sbom-cyclonedx.json`

This release marks QASP's production readiness with enterprise-grade security, compliance frameworks, and quantum-resistant cryptography.

#### Upgrade Notes
- Set `QKD_HARDWARE_ENABLED=true` for quantum key distribution
- Configure hardware vendors via `QKD_VENDOR` environment variable
- Review `docs/COMPLIANCE_GUIDE.md` for certification requirements
- Monitor QKD status via `/hardware/status` endpoint

#### Breaking Changes
- Server version updated to 1.0.0
- QKD hardware detection requires explicit configuration
- New audit pipeline may require compliance environment setup

#### Known Limitations
- Hardware QKD vendors require proprietary SDK integration
- FIPS 140-3 validation pending final cryptographic module testing
- Common Criteria certification requires formal evaluation

---

## Future Roadmap

### v1.1.0 (Planned Q1 2026)
- Additional QKD vendor integrations
- FIPS 140-3 validated cryptographic modules
- Enhanced performance optimizations
- Container security scanning integration

### v2.0.0 (Planned Q2 2026)
- MLS (Messaging Layer Security) protocol integration
- Post-quantum TLS 1.3 implementation
- Hardware-accelerated cryptography support
- Advanced key management lifecycle features
