# Threat model (initial)

## Assets
- Long-term private keys (PQC keys)
- Session symmetric keys
- API tokens / access credentials
- Data at rest and data in transit

## Adversary capabilities
- Passive eavesdrop & store (harvest-now, decrypt-later).  [oai_citation:10‡0725_military_and_security_dimensions_of_quantum_technologies_0.pdf](sediment://file_00000000c67461f6b084a086ce34ccc0)
- Active network MITM (including attempts to compromise trusted nodes in QKD chains).
- Supply chain compromise or hardware backdoor.
- Side-channel attacks against QRNG or QKD hardware.
- Local compromise of HSM or host.
- Insider threats (privileged users with legitimate access abusing trust).
- Cloud KMS abuse (misconfigured permissions, compromised cloud credentials).

## Attack surfaces & mitigations
1. **Harvest-now** — Mitigation: PQC migration + forward secrecy via ephemeral KEM per session; combine with QKD-derived symmetric secrets for high-assurance links.  [oai_citation:11‡NIST Computer Security Resource Center](https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization?utm_source=chatgpt.com)
2. **Trusted-node compromise (QKD)** — Mitigation: design network to minimize trusted node count; log and monitor node health and certificate attestation; use entanglement-based or repeater approach only where available and tested. (See ISO/ITU guidance on node security.)  [oai_citation:12‡ITU](https://www.itu.int/epublications/publication/itu-t-x-1713-2024-04-security-requirements-for-the-protection-of-quantum-key-distribution-nodes?utm_source=chatgpt.com)
3. **Side channels / hardware** — Mitigation: hardware vetting, tamper evidence, QDM inspections for physical device modification where appropriate.  [oai_citation:13‡0725_military_and_security_dimensions_of_quantum_technologies_0.pdf](sediment://file_00000000c67461f6b084a086ce34ccc0)
4. **Insider threats** — Mitigation: principle of least privilege; comprehensive audit logging and monitoring; QASP audit trail for all key operations and access attempts; HSM integration to limit direct key access.
5. **Supply-chain compromise** — Mitigation: software bill of materials (SBOM); verified builds with reproducible artifacts; continuous integration with security scans; regular dependency updates and vulnerability assessments.
6. **Cloud KMS abuse** — Mitigation: minimal IAM permissions; encryption context validation; key rotation policies; audit logs for all KMS operations in QASP keystore abstraction.
