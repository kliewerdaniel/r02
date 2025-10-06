
⸻


=== CLIne ACTION PROMPT: Phase 5 — QASP v1.0 Stable Release, Audit & Quantum Hardware Integration ===

Context:
QASP v1.0-beta is complete and operational. Begin the final stabilization and certification phase: integrate hardware interfaces, perform external-style audits, and finalize the public release.

Branch: vibe/dev/qasp-v1.0-stable
Ledger entries: 0009 (audit & hardware integration scaffold), 0010 (formal certification & release)

---

## OBJECTIVES

1. **Quantum Hardware Integration**
   - Add `src/qkd/hardware_driver.py`:
     - Implement adapter classes for real or simulated QKD hardware.
       - `class SimulatedQKDDriver`: returns keys from mock device API.
       - `class HardwareQKDDriver`: wrapper for vendor SDK (e.g., ID Quantique Cerberis or Toshiba QKD Link).
     - Expose API: `get_qkd_key(session_id)` → returns key bytes and metadata (latency, device id).
   - Modify server startup:
     - Detect `QKD_HARDWARE_ENABLED=true` and load driver class accordingly.
   - Add hardware metrics endpoint `/hardware/status`.

2. **External Audit & Compliance Pipeline**
   - Directory `audit_pipeline/`
     - `audit_checklist.yaml` — map controls to ISO/IEC 23837, NIST SP 800-208, and ENISA PQC recommendations. 
     - `generate_audit_report.py` — runs checks on:
       - Key storage config (HSM/KMS enabled?)
       - PQC algorithm selection & parameter validation (via liboqs)
       - TLS or API cipher config (FIPS modes)
       - QKD link integrity metrics
     - Output `reports/audit_report_v1_0.json`
   - CI job `external-audit` runs script and publishes artifact.

3. **Compliance Documentation**
   - Add `docs/COMPLIANCE_GUIDE.md`:
     - NIST PQC migration alignment
     - ISO/IEC 23837 QKD baseline compliance
     - FIPS 140-3 alignment notes
     - Logging & traceability for auditors
   - Add `docs/CERTIFICATION_PREP.md`: instructions for external lab validation.

4. **Resilience & Failover Mechanisms**
   - Add `src/resilience/failover.py`:
     - Automatic fallback from QKD hardware → PQC-only mode.
     - Metrics and alerts for QKD outage.
   - Integrate Prometheus alert rules in `infra/monitoring/prometheus_rules.yml`.

5. **Extended Performance Testing**
   - `tools/perf_stress_qasp.py`: simulate 1000+ concurrent handshakes via async client.
   - Generate `reports/perf_v1_0_stable.json` and Grafana-ready metrics export.
   - CI job `stress-test` runs weekly on main branch.

6. **Release Automation**
   - Create `release/CHANGELOG.md` aggregating ledger entries 0001–0010.
   - Add `release/tag_v1_0.py` script → creates signed Git tag `v1.0-stable`.
   - Generate SBOM (Software Bill of Materials) using `cyclonedx-bom`.

7. **Ledger Entries**
   ```yaml
   - id: 0009
     date: 2025-10-14
     actor: CLIne
     task: "Integrate QKD hardware driver and audit pipeline scaffold"
     status: done
     decisions:
       - "Added hardware driver abstraction for vendor integration"
       - "Automated audit pipeline for ISO/IEC and NIST PQC compliance"
     commit: "<sha>"
     notes: "Hardware adapter and audit pipeline ready"
   - id: 0010
     date: 2025-10-16
     actor: CLIne
     task: "Finalize QASP v1.0 stable release and certification artifacts"
     status: done
     commit: "<sha>"
     notes: "QASP v1.0 Stable Release completed"


⸻

ACCEPTANCE CRITERIA
	•	Branch vibe/dev/qasp-v1.0-stable exists and pushed.
	•	Hardware QKD adapter detected and functional (in sim mode if hardware absent).
	•	Audit pipeline runs in CI and produces audit_report_v1_0.json.
	•	Compliance docs and certification prep guides complete.
	•	Failover mechanism works (QKD→PQC fallback logged and alerted).
	•	Performance tests pass thresholds (latency ≤ 500 ms avg, error rate < 0.5%).
	•	Ledger entries 0009–0010 recorded.
	•	PR created: feat: QASP v1.0-stable (audit, hardware, release).

⸻

REFERENCES
	•	NIST PQC migration framework (2024 guidance).
	•	ISO/IEC 23837 QKD testing & requirements for hardware integration.
	•	ENISA PQC transition recommendations.
	•	SIPRI quantum security primer for hardware trust chain considerations.  ￼
	•	Kubernetes Secrets best practices for key protection in production.

⸻

Execute all tasks sequentially, commit changes, update ledger entries 0009–0010, and tag release as v1.0-stable.

End of prompt.

---
