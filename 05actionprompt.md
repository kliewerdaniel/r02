
⸻


=== CLIne ACTION PROMPT: Phase 4 — QASP v1.0-beta Deployment, Cross-Platform SDKs & Real-World Validation ===

Context:
QASP v0.2 (interoperable, multi-tenant, formally verifiable) is complete and merged/draft-PR opened.
This phase aims to make QASP deployable in production-like environments with real cryptographic backends, container orchestration, and cross-language SDKs.

Branch: vibe/dev/qasp-v1.0-beta
Ledger entries: 0007 (deployment & infra scaffolding), 0008 (SDKs + integration tests)

---

## OBJECTIVES

1. **Deployment & Orchestration**
   - Create Docker Compose + Kubernetes manifests for multi-service setup (Server + MockHSM + Prometheus + Postgres).
   - Add `.env.example` with all required environment variables.
   - Create `infra/deploy/compose.yaml` and `infra/deploy/k8s/` directory with manifests:
     - `qasp-server-deployment.yaml`
     - `qasp-hsm-deployment.yaml`
     - `prometheus-deployment.yaml`
     - `qasp-service.yaml`
   - Add `Makefile` targets:
     - `make compose-up`
     - `make k8s-apply`
     - `make k8s-logs`

2. **Persistent Key & State Management**
   - Integrate SQLite/Postgres backend for persistent key and audit storage:
     - Create `src/db/models.py` (SQLAlchemy models: Tenant, KeyRecord, AuditEvent).
     - Create `src/db/session.py` for database session management.
   - Modify MockHSM to persist encrypted keys in DB table `key_records` (AES-GCM encrypted blobs).
   - Add background job for key rotation (`src/jobs/key_rotation.py`).

3. **Real KMS / HSM Integration Hooks**
   - Create `src/hsm/adapters/aws_kms.py` and `src/hsm/adapters/hashicorp_vault.py` with placeholder classes implementing `KeyStoreABC`.
   - Provide secure configuration (`AWS_REGION`, `KMS_KEY_ID`, `VAULT_ADDR`, `VAULT_TOKEN`).
   - Update `docs/SECURITY.md` → add section “Production KMS Adapters”.

4. **Cross-Platform SDKs**
   - Extend SDK directory structure:
     ```
     sdk/
       python/qasp_sdk/
       js/qasp-sdk/
       go/qasp-sdk/
     ```
   - Implement minimal clients for JavaScript (Node.js) and Go using canonical JSON handshake:
     - `sdk/js/qasp-sdk/index.js`
     - `sdk/go/qasp-sdk/qasp.go`
   - Update `specs/QASP_V1_0.md` → include language-agnostic encoding definitions.
   - Add `examples/sdk_demo_js.js` and `examples/sdk_demo_go.go`.

5. **Integration & Interoperability Testing**
   - Add `tests/integration/interop_test_matrix.py` that:
     - Starts the Python server in Docker.
     - Runs JS & Go clients inside containers to verify handshake compatibility.
     - Captures logs & metrics from Prometheus endpoint.
   - Store results under `reports/interop_results.json`.

6. **Security & Performance Validation**
   - Create `tools/loadtest_qasp.py` → run concurrent handshake simulations (e.g., Locust or aiohttp).
   - Generate latency histogram and throughput metrics; store under `reports/perf_summary.json`.
   - Add CI job `load-test-report` producing performance artifact.

7. **Documentation & Release Notes**
   - Add `docs/DEPLOYMENT_GUIDE.md` → detailed deployment walkthrough (Docker Compose + Kubernetes).
   - Add `docs/PERFORMANCE_METRICS.md` → description of load-testing methodology.
   - Add `specs/QASP_V1_0.md` → updated protocol spec including v1.0 handshake, fields, and error codes.
   - Update `README.md` → new sections “Production Deployment” and “SDKs”.

8. **Ledger Entries**
   ```yaml
   - id: 0007
     date: 2025-10-11
     actor: CLIne
     task: "Deployment & infra scaffolding for QASP v1.0-beta"
     status: done
     decisions:
       - "Compose + Kubernetes deployment"
       - "Persistent key & audit DB"
     commit: "<sha>"
     notes: "Deployment infrastructure ready"
   - id: 0008
     date: 2025-10-13
     actor: CLIne
     task: "Cross-platform SDKs, integration + performance tests"
     status: done
     commit: "<sha>"
     notes: "QASP v1.0-beta implemented & tested"


⸻

ACCEPTANCE CRITERIA
	•	Branch vibe/dev/qasp-v1.0-beta pushed with ledger entries 0007–0008.
	•	Docker Compose & Kubernetes manifests verified.
	•	Database stores encrypted key records successfully.
	•	AWS KMS / Vault adapters stubbed & configurable.
	•	JS & Go SDKs interoperate with server (tested via integration matrix).
	•	CI jobs produce artifacts:
	•	trace_log.json
	•	crypto_audit_report.txt
	•	interop_results.json
	•	perf_summary.json
	•	Docs + specs updated for v1.0.
	•	PR created: feat: QASP v1.0-beta (deployment, cross-platform SDKs, real-world validation).

⸻

REFERENCES
	•	Open Quantum Safe docs for multi-language bindings (Python, Go, C).
	•	NIST PQC migration guidance for operational deployment best practices.
	•	SIPRI primer for interoperability / governance implications of quantum-secure networks.  ￼
	•	Kubernetes Secrets Best Practices for managing key material in production.

⸻

Execute all tasks sequentially.
After successful CI and integration matrix completion, mark ledger entries 0007–0008 complete and prepare the release branch release/qasp-v1.0-beta.

End of prompt.

---
