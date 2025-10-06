Vibe Ledger (human+machine readable)
•	Format: YAML sections, one per ledger entry. CLIne should append new entries.

Example entry (seeded by CLIne on repo init):

- id: 0001
  date: 2025-10-06
  actor: CLIne
  task: "create initial repo templates"
  status: done
  files_created:
    - README.md
    - docs/SECURITY.md
    - docs/THREAT_MODEL.md
    - API_SPEC.md
  decisions:
    - "Adopt hybrid PQC + QKD-inspired pattern for session keys (QASP v0.1)."
  rationale:
    - "Follow NIST PQC guidance and SIPRI primer for QKD tradeoffs."
  commit: "c3db1b8"
  notes: "Use HSM for private key storage; pilot Kyber + Dilithium."

- id: 0002
  date: 2025-10-06
  actor: CLIne
  task: "initial dev implementation: env, crypto wrappers, qkd mock, server/client, tests"
  status: done
  files_created:
    - requirements.txt
    - Dockerfile
    - Makefile
    - src/qasp/crypto.py
    - src/qkd/mock_qkd.py
    - src/server/main.py
    - src/client/demo_client.py
    - tests/test_qasp_handshake.py
    - .github/workflows/ci.yml
    - docs/DEV_RUNBOOK.md
  decisions:
    - "Use liboqs-python for PQC prototyping"
    - "FastAPI for server"
    - "HKDF + XChaCha20-Poly1305 AEAD"
  rationale:
    - "As per NIST PQC selections and SIPRI design guidance."
  commit: "97a9007"
  notes: "liboqs is prototyping-only; production requires HSM & vendor validated libs."

- id: 0003
  date: 2025-10-06
  actor: CLIne
  task: "Design and scaffold HSM/KMS abstraction + telemetry"
  status: done
  decisions:
    - "MockHSM with AES-GCM encryption and environment master key"
    - "Structlog JSON logs + Prometheus metrics"
    - "Crypto-agility with environment variables KEM_ALG/SIG_ALG"
    - "Rate limiting and request signature middleware"
  files_changed:
    - src/hsm/abstract_store.py
    - src/hsm/mock_hsm.py
    - src/telemetry/logging_config.py
    - src/telemetry/metrics.py
    - src/config/crypto_config.py
    - src/server/middleware.py
  commit: "4eccc2d"
  notes: "Phase 2 hardening scaffold complete; stores server keys in HSM on startup."

- id: 0004
  date: 2025-10-06
  actor: CLIne
  task: "Implement crypto-agility config, audit pipeline, rate-limiting"
  status: done
  decisions:
    - "CI job 'audit-crypto-params' with PQC parameter validation"
    - "Crypto config validation at startup"
    - "Rate limit: 10 requests/minute per client"
    - "Optional request signature middleware for replay protection"
  files_changed:
    - src/qasp/crypto.py
    - src/server/main.py
    - tools/audit_crypto_params.py
    - .github/workflows/ci.yml
    - docs/THREAT_MODEL.md
    - docs/SECURITY.md
    - docs/AUDIT_PIPELINE.md
    - README.md
  commit: "be7143d"
  notes: "Implementation & audit pipeline integrated; server uses HSM when HSM_ENABLED=true."

- id: 0005
  date: 2025-10-09
  actor: CLIne
  task: "Design QASP v0.2 interoperability & multi-tenant model"
  status: done
  decisions:
    - "Canonical JSON for cross-language compatibility"
    - "Tenant isolation enforced in key derivation & metrics"
  files_created:
    - specs/QASP_V0_2.md
    - src/interop/qasp_interop.py
    - src/formal/qasp_model.py
    - docs/FORMAL_VERIFICATION.md
  commit: "ba8d4c7"
  notes: "Interoperability scaffolding complete"

- id: 0006
  date: 2025-10-10
  actor: CLIne
  task: "Implement v0.2 handshake, SDK, and formal verification hooks"
  status: done
  decisions:
    - "Multi-tenant key storage with tenant_id partitions"
    - "Session tokens bound to tenant_id"
    - "Trace logging for formal analysis"
    - "Python SDK with interoperability functions"
  files_created:
    - sdk/python/qasp_sdk/
    - examples/sdk_demo.py
    - tests/conformance/test_serialization.py
    - tests/formal/test_trace_log.py
    - tests/test_multi_tenant.py
  files_changed:
    - src/hsm/abstract_store.py
    - src/hsm/mock_hsm.py
    - src/qasp/crypto.py
    - src/server/main.py
    - src/server/middleware.py
    - src/telemetry/metrics.py
    - docs/SECURITY.md
    - README.md
    - ci/pipeline.yaml
  commit: "ba8d4c7"
  notes: "QASP v0.2 complete — interoperable & formally traceable"

•	New entries MUST include: id, date, actor, task, status, files_changed, commit, notes.
