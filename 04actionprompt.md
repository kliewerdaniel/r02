
⸻


=== CLIne ACTION PROMPT: Phase 3 — QASP v0.2 Interoperability, Multi-Tenancy & Formal Verification Hooks ===

Context:
Phases 1–2 delivered a working QASP v0.1 prototype and a hardened service with HSM/KMS, observability, and crypto-agility.
Now build QASP v0.2, focusing on:
- cross-implementation interoperability
- secure multi-tenant key isolation
- integration with external verification tools
- automated conformance testing
- documentation for third-party implementers

Branch name: vibe/dev/qasp-v0.2
Ledger entries: 0005 (design & scaffolding), 0006 (implementation & verification)

---

## OBJECTIVES

1. **Multi-Tenant Key Domains**
   - Add per-tenant key namespaces with independent HSM partitions.
   - Enforce tenant isolation in all key derivation, metrics, and logs.
   - Add tenant ID to session tokens, audit logs, and `/metrics` labels.

2. **Interoperability Layer**
   - Create `src/interop/qasp_interop.py` with:
     - `serialize_handshake()` / `deserialize_handshake()` using canonical JSON or CBOR encoding.
     - `validate_message_schema()` per QASP v0.2 spec.
   - Define version field in every QASP message (`"qasp_version": "0.2"`).

3. **Formal Verification Hooks**
   - Create `src/formal/qasp_model.py` exporting symbolic constants and handshake states.
   - Implement a TLA+-ready or ProVerif-ready trace log writer (`write_trace_log()`) capturing send/receive events.
   - Add CI job `formal-trace-export` to emit `trace_log.json` and upload artifact.

4. **External Client SDK**
   - Add minimal Python client SDK under `sdk/python/qasp_sdk/`.
   - Functions: `register_client()`, `init_handshake()`, `challenge()`, `request_resource()`.
   - Include proper docstrings so external teams can import it.

5. **Conformance Tests**
   - Directory: `tests/conformance/`
   - Tests comparing message serialization against reference vectors in `specs/QASP_V0_2.md`.
   - Add golden-file tests verifying cross-language stability (use canonical JSON ordering).

6. **Documentation**
   - Create `specs/QASP_V0_2.md` — formalized specification of v0.2 including message schemas, allowed algorithms, and error codes.
   - Update `README.md` → add “v0.2 Interoperability Guide”.
   - Update `docs/SECURITY.md` → new section “Multi-Tenant Key Isolation”.
   - Add `docs/FORMAL_VERIFICATION.md` → instructions for exporting & analyzing trace logs.

7. **Ledger Entries**
   ```yaml
   - id: 0005
     date: 2025-10-09
     actor: CLIne
     task: "Design QASP v0.2 interoperability & multi-tenant model"
     status: done
     decisions:
       - "Canonical JSON for cross-language compatibility"
       - "Tenant isolation enforced in key derivation & metrics"
     commit: "<sha>"
     notes: "Interoperability scaffolding complete"
   - id: 0006
     date: 2025-10-10
     actor: CLIne
     task: "Implement v0.2 handshake, SDK, and formal verification hooks"
     status: done
     commit: "<sha>"
     notes: "QASP v0.2 complete — interoperable & formally traceable"


⸻

IMPLEMENTATION TASKS

A. Multi-Tenant HSM Extensions
	•	Extend KeyStoreABC with tenant context: all methods accept tenant_id.
	•	MockHSM: partition its storage dict by tenant namespace.
	•	Add /admin/tenants endpoint for listing & rotating tenant partitions.

B. Session Token Changes
	•	Add field "tenant_id" inside the QASP session token payload.
	•	Modify AEAD encryption to bind tenant_id in associated data (AAD).

C. Interoperability Encoding
	•	Define canonical JSON schema (sorted keys, no whitespace).
	•	Add validation script tools/validate_vectors.py to check message conformity.

D. Formal Verification Hooks
	•	src/formal/qasp_model.py exports constants: STATES = [“INIT”, “CHALLENGE”, “ESTABLISHED”]
	•	write_trace_log(event_type, payload) appends to JSON array under logs/trace_log.json.
	•	CI job formal-trace-export runs after tests and uploads artifact.

E. SDK Packaging
	•	sdk/python/setup.py for installable package.
	•	Add example usage in examples/sdk_demo.py.

F. Tests
	•	Expand pytest suite:
	•	tests/test_multi_tenant.py
	•	tests/conformance/test_serialization.py
	•	tests/formal/test_trace_log.py
	•	Ensure CI runs all and artifacts produced (trace_log.json, crypto_audit_report.txt).

⸻

ACCEPTANCE CRITERIA
	•	Branch vibe/dev/qasp-v0.2 pushed with commits 0005–0006 logged.
	•	Multi-tenant HSM abstraction functional.
	•	Interop serialization passes conformance tests.
	•	SDK package builds and imports without errors.
	•	formal-trace-export job produces valid trace log artifact.
	•	Docs updated and versioned spec specs/QASP_V0_2.md present.
	•	PR created: feat: QASP v0.2 (interop, multi-tenant, formal-verification).

⸻

REFERENCES
	•	Open Quantum Safe liboqs for supported algorithm IDs (use for schema constants).
	•	NIST PQC algorithm categories and parameter sets for configurable agility.
	•	SIPRI primer for policy/verification implications of trusted-node quantum networks.  ￼
	•	TLA+ / ProVerif docs for modeling communication protocols (for trace-export format alignment).

⸻

Execute all tasks sequentially. After successful CI and PR creation, mark ledger entries 0005–0006 complete and report readiness for QASP v0.2 release.

End of prompt.

---
