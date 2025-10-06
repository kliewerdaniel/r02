# AI Security Advisor for QASP v2.0

## Overview
The AI Security Advisor (implemented in `src/ai_threat/monitor.py`) is a lightweight policy engine that integrates threat intelligence into cryptographic decision-making. It uses a simulated LLM agent to recommend algorithm rotations based on real-time risk assessments.

## Reasoning Model
- **Inputs**: Threat feeds (`threat_feeds/`) containing JSON-structured data on PQC algorithm risks, hardware incidents, and latency metrics.
- **Processing**:
  1. Aggregate feeds into a unified threat dataset.
  2. Apply heuristic decision trees (mock LLM simulation):
     - High-risk indicators (e.g., NIST-graded vulnerabilities) trigger stronger algorithm recommendations.
     - Performance issues (e.g., decryption latency spikes) suggest optimized variants.
     - Fallback: No action if risk levels are acceptable.
- **Outputs**: Recommendations logged in `src/ai_threat/recommendations.log` with timestamps, threat data, and rationale.

## Safeguards
- **Human Oversight**: All recommendations require manual approval before execution. No automatic rotations.
- **Audit Logging**: Full traceability in ledger; report generation for compliance.
- **Fallback Behavior**: If LLM simulation fails or feeds are unavailable, maintain current algorithms.
- **Rate Limiting**: Recommendations capped at once per day to avoid disruption.
- **Security Boundaries**: Runs in isolated environment; no network access to sensitive systems.

## Example Reasoning
- **Input Threat**: {"risk_level": "high", "issue": "PQC key recovery vulnerability"}
- **Rationale**: High-risk threats to current KEM necessitate upgrade to strengthen post-quantum resistance.
- **Recommendation**: "Rotate to ML-KEM-1024 on all affected tenancies."

## Future Enhancements
- Integrate real LLM (e.g., OpenAI API) for advanced pattern recognition.
- Add probabilistic model for risk quantification.
- Support multi-modal inputs (text, metrics, anomaly detection).

References: NIST IR 8273 on AI for Cybersecurity, ENISA AI Guidelines.
