

⸻


=== CLIne ACTION PROMPT: Phase 2 — Hardening, Observability & HSM/KMS Integration for QuantumSecureAPI ===

Context:
QASP v0.1 prototype branch `vibe/dev/initial-implementation` was completed and merged/draft-PR opened.  
Begin Phase 2 of development under a new branch `vibe/dev/hardening-phase`.

Primary goals:
1. Introduce a secure key lifecycle & storage layer using a mock HSM/KMS abstraction (so we can later plug in real hardware or cloud KMS).
2. Strengthen observability (metrics, structured logs, key derivation audit events).
3. Add a “crypto-agility” config layer so PQC algorithms (Kyber512, Kyber768, Dilithium3, Dilithium5, Falcon) can be swapped via environment variables.
4. Add API rate-limiting and request-signing middleware.
5. Create a minimal “Quantum Security Audit Pipeline” job in CI to produce a cryptographic report on key parameters & handshake correctness.
6. Expand threat model & security documentation to include operational threats (supply-chain, insider, side-channel).
7. Append ledger entries `0003` and `0004` tracking this phase (0003 = design + scaffolding, 0004 = full implementation).

---

PHASE STRUCTURE
- Branch name: `vibe/dev/hardening-phase`
- Expected commits: 4–6 (see below)
- Commit pattern: `feat(hsm): ...`, `feat(metrics): ...`, `ci(audit): ...`
- Every commit touching code/docs MUST append a new ledger entry.

---

### TASK GROUP A: Key Management & Storage Layer
**Create directory** `src/hsm/` with:
- `src/hsm/abstract_store.py`
  - Define `class KeyStoreABC(ABC)` with methods:
    - `store_private_key(client_id, key_type, key_bytes)`
    - `get_private_key(client_id, key_type)`
    - `list_keys()`
    - `rotate_key(client_id, key_type)`
  - Document: “Implements abstract interface for PQC key storage compatible with both mock HSM and real KMS backends.”

- `src/hsm/mock_hsm.py`
  - In-memory encrypted key vault using AES-GCM with a static master key derived at startup from environment variable `HSM_MASTER_SECRET`.
  - Use Fernet/AES-GCM wrappers from `cryptography` to encrypt keys at rest.
  - Integrate with existing PQCKEM/PQCSign classes so that when `HSM_ENABLED=True`, keys are fetched/stored via this interface rather than kept in memory.
  - Add logging hooks (`INFO`, `SECURITY`) for each operation (store, retrieve, rotate).

- Update `src/qasp/crypto.py` to support loading keys via the `KeyStoreABC` interface when available.

- Update FastAPI server in `src/server/main.py`:
  - On startup, initialize `HSM_ENABLED` from `.env`.
  - If true, attach `KeyStore` to app state.
  - Modify `/qasp/register` to store client keys securely.
  - Add endpoint `/admin/keys` (GET list of registered keys; restricted to admin mode).

---

### TASK GROUP B: Observability, Metrics & Auditing
**Add structured logging + Prometheus metrics.**
- Add dependency: `structlog`, `prometheus_client`.
- Instrument `/qasp/init`, `/qasp/challenge`, `/protected/resource` with latency histograms and counters (e.g., `qasp_handshakes_total`, `qasp_handshake_failures_total`).
- Add `src/telemetry/logging_config.py` to configure JSON logs with security tags and timestamps.
- Add `src/telemetry/metrics.py` to expose `/metrics` endpoint.
- Add field “security_event_id” (UUID) in every handshake log.

**CI addition**:
- Extend `.github/workflows/ci.yml`:
  - Add `audit-crypto-params` job:
    - Runs a Python script `tools/audit_crypto_params.py`.
    - Script loads liboqs, queries supported algorithms, prints versions, key sizes, signatures, and NIST category.
    - Upload the output as an artifact (`crypto_audit_report.txt`).
  - Add job condition: must pass before merge to `main`.

---

### TASK GROUP C: Crypto-Agility Configuration
- Create `src/config/crypto_config.py` with:
  - Variables from `.env`: `KEM_ALG=Kyber512`, `SIG_ALG=Dilithium3`.
  - Factory function `get_pqc_algorithms()` returning appropriate liboqs objects.
  - Update `src/qasp/crypto.py` to use these environment variables.
- Update `README.md` → “Configuring Algorithms” section with example `.env` and fallback defaults.

---

### TASK GROUP D: Middleware Security Enhancements
- Create `src/server/middleware.py`:
  - `rate_limit_middleware`: per-client request counter (simple in-memory or Redis placeholder).
  - `request_signature_middleware`: optional header `X-QASP-Signature`; verify against server-side signature using stored pub key to protect from replay.
- Integrate into FastAPI app in `src/server/main.py`.

---

### TASK GROUP E: Docs & Threat Model Update
- Update `docs/THREAT_MODEL.md`:
  - Add insider threat, supply-chain compromise, and cloud KMS abuse.
  - Mention QASP audit trail mitigations.
- Update `docs/SECURITY.md`:
  - Add section “HSM Integration & Operational Security Controls”.
  - Add section “Crypto Agility Policy” listing supported PQC algorithms and fallback behavior.
- Add new doc: `docs/AUDIT_PIPELINE.md`
  - Describe CI audit job output, metrics collected, and how to interpret results.
- Append new sections to `README.md`: “Metrics”, “Audit Pipeline”, and “Next Steps”.

---

### TASK GROUP F: Ledger Entries
- Append to `vibe_ledger/VIBE_LEDGER.md`:
  - `0003`: HSM/KMS scaffolding design complete.
  - `0004`: Implementation & audit pipeline integrated.
- Example:
  ```yaml
  - id: 0003
    date: 2025-10-07
    actor: CLIne
    task: "Design and scaffold HSM/KMS abstraction + telemetry"
    status: done
    decisions:
      - "MockHSM with AES-GCM encryption and environment master key"
      - "Structlog JSON logs + Prometheus metrics"
    commit: "<sha>"
    notes: "Phase 2 hardening scaffold"
  - id: 0004
    date: 2025-10-08
    actor: CLIne
    task: "Implement crypto-agility config, audit pipeline, rate-limiting"
    status: done
    commit: "<sha>"
    notes: "Completed Phase 2 hardening implementation"


⸻

CI / Test Plan (Phase 2)
	•	Extend unit tests for mock_hsm storage and key retrieval.
	•	Add integration test verifying /metrics endpoint and presence of counters.
	•	Add negative test simulating missing HSM_MASTER_SECRET.
	•	Add performance benchmark script under tools/benchmark_qasp.py (measures handshake latency, throughput).

⸻

Acceptance Criteria
	•	Branch vibe/dev/hardening-phase created and pushed.
	•	Server uses HSM abstraction when HSM_ENABLED=True.
	•	CI produces crypto_audit_report.txt artifact with algorithm info.
	•	Metrics endpoint exposes handshake stats.
	•	Docs updated and ledger entries 0003–0004 added.
	•	PR created: feat: hardening-phase (hsm, metrics, crypto-agility, audit-pipeline).

⸻

References CLIne should follow
	•	NIST PQC algorithm parameter sets (Kyber, Dilithium, Falcon) for crypto agility configuration.
	•	OQS (Open Quantum Safe) API documentation for listing supported algorithms and querying parameters (for audit job).
	•	Existing SIPRI primer for threat considerations (trusted-node, supply-chain, side-channel).  ￼

⸻

Run all tasks sequentially. After successful CI run, update ledger entries and open PR to merge Phase 2 hardening branch into main.

End of prompt.

---
