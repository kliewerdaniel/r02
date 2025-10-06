=== CLIne MASTER PROMPT: Generate Vibe-Coding Repo Templates for a Quantum-Aware API Security Project ===

Goal:
Create a new git repo named "QuantumSecureAPI" and add a complete set of template files in the repository root. This repo is a design + implementation skeleton for an API service that replaces JWT-style endpoint auth with a hybrid quantum-aware security approach (PQC + QKD/QRNG layered design). Produce content exactly as specified below (fill placeholders noted with {{...}}). Commit each file and add an initial ledger entry.

Style / constraints:
- Use clear, copyable Markdown, YAML or OpenAPI fragments for docs.
- Wherever cryptographic choices are recommended, reference existing standards and warn: "use vetted libraries, do not roll your own crypto".
- Provide a "vibe ledger" (human + machine readable) to track CLIne progress and decisions.
- Create CI/QA templates and a security test plan focused on quantum threats (harvest-now, trusted-node compromise, side channels).
- Include a spec for an experimental "Quantum API Security Protocol (QASP) v0.1" (handshake, message flows, fields, fallback).
- Where the design is inspired by the attached SIPRI primer, include a short reference line to that document.

Files to create (root-level). For each file, write the exact content between the separators.

================================================================================
FILE: README.md
================================================================================
# QuantumSecureAPI

**Purpose.** Prototype of an API service secured by a hybrid, quantum-aware security stack: Post-Quantum Cryptography (PQC) for authentication + Quantum Key Distribution (QKD) / Quantum Random Number Generator (QRNG) elements where available to derive session symmetric keys (the "QASP" approach).

**Why this project.**
- Protects against harvest-now, decrypt-later attacks and future cryptanalysis.  [oai_citation:2‡0725_military_and_security_dimensions_of_quantum_technologies_0.pdf](sediment://file_00000000c67461f6b084a086ce34ccc0)
- Follows current PQC standardization and transition guidance (NIST, ENISA).  [oai_citation:3‡NIST Computer Security Resource Center](https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization?utm_source=chatgpt.com)
- Provides a reproducible set of docs, ledger and tests for "vibe coding" development.

**Repo layout (created by CLIne)**
- `README.md` (this file)
- `API_SPEC.md` (OpenAPI skeleton + QASP security scheme)
- `docs/SECURITY.md`, `docs/THREAT_MODEL.md`, `docs/QKD_DESIGN.md`, `docs/PQC_PLAN.md`
- `vibe_ledger/VIBE_LEDGER.md`
- `specs/IMPLEMENTATION_GUIDE.md`, `specs/OPERATIONAL_RUNBOOK.md`
- `templates/` (issue/PR templates)
- `ci/` (CI job templates)
- `src/` (app skeleton)
- `tests/` (test and adversary/emulation plans)

**Quick start (for developers)**
1. `git init && git checkout -b vibe/init`
2. CLIne will create the files below and commit them as `chore:init-templates`.
3. Read `vibe_ledger/VIBE_LEDGER.md` for tasks and the current sprint.

================================================================================
FILE: docs/SECURITY.md
================================================================================
# Security overview & rationale

This document outlines the security architecture, assumptions and operational guidance
for QuantumSecureAPI.

## High-level strategy
1. **PQC baseline**: Use standardized PQC algorithms for authentication and signatures. NIST has published PQC standards and recommends organizations start the transition now.  [oai_citation:4‡NIST Computer Security Resource Center](https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization?utm_source=chatgpt.com)  
2. **Quantum layer (where available)**: When a QKD link or a QRNG is available between two endpoints, use the QKD/QRNG output as an additional entropy/source to seed session keys — layered with PQC-derived KEM results. SIPRI and other primers recommend layering QKD on top of PQC for high-assurance links.  [oai_citation:5‡0725_military_and_security_dimensions_of_quantum_technologies_0.pdf](sediment://file_00000000c67461f6b084a086ce34ccc0)
3. **Hybrid approach**: All production-grade deployments MUST implement PQC for broad compatibility; QKD is an optional high-value add for selected links (e.g., cross-data-center control plane). ISO/IEC defines baseline requirements and testing for QKD modules.  [oai_citation:6‡ISO](https://www.iso.org/standard/77097.html?utm_source=chatgpt.com)

## Key lifecycle & storage
- Use an enterprise KMS/HSM/TPM to store long-term keys. Do not persist raw QKD outputs without HSM controls.
- Private keys for PQC algorithms (example: Kyber/Dilithium) must be stored only in an HSM or protected keystore.  [oai_citation:7‡NIST Computer Security Resource Center](https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization?utm_source=chatgpt.com)

## Recommended primitives (initial prototype choices)
- KEM / key establishment: **CRYSTALS-Kyber** (example).  [oai_citation:8‡NIST Computer Security Resource Center](https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization?utm_source=chatgpt.com)  
- Digital signatures / authentication: **CRYSTALS-Dilithium** (example).  [oai_citation:9‡NIST Computer Security Resource Center](https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization?utm_source=chatgpt.com)  
- Symmetric cipher & AEAD: AES-GCM or XChaCha20-Poly1305 for application payloads; rotate keys frequently and derive using HKDF over all sources (KEM shared secret || QRNG || QKD key material if present).
- Randomness source: Prefer a certified **QRNG** for seeding high-entropy pools when hardware is available; otherwise use OS CSPRNG seeded by entropy-harvesting best practices.

**Warning:** use vetted libraries (libs that implement FIPS/PQC standards) and hardware HSMs. Do NOT implement crypto primitives yourself.

================================================================================
FILE: docs/THREAT_MODEL.md
================================================================================
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

## Attack surfaces & mitigations
1. **Harvest-now** — Mitigation: PQC migration + forward secrecy via ephemeral KEM per session; combine with QKD-derived symmetric secrets for high-assurance links.  [oai_citation:11‡NIST Computer Security Resource Center](https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization?utm_source=chatgpt.com)  
2. **Trusted-node compromise (QKD)** — Mitigation: design network to minimize trusted node count; log and monitor node health and certificate attestation; use entanglement-based or repeater approach only where available and tested. (See ISO/ITU guidance on node security.)  [oai_citation:12‡ITU](https://www.itu.int/epublications/publication/itu-t-x-1713-2024-04-security-requirements-for-the-protection-of-quantum-key-distribution-nodes?utm_source=chatgpt.com)  
3. **Side channels / hardware** — Mitigation: hardware vetting, tamper evidence, QDM inspections for physical device modification where appropriate.  [oai_citation:13‡0725_military_and_security_dimensions_of_quantum_technologies_0.pdf](sediment://file_00000000c67461f6b084a086ce34ccc0)

================================================================================
FILE: docs/QKD_DESIGN.md
================================================================================
# QKD design notes (for high-value links)

- Options:
  - **Point-to-point fibre QKD** with trusted repeater nodes (first-generation approach). Practical, but requires trust in nodes. SIPRI notes this trade-off.  [oai_citation:14‡0725_military_and_security_dimensions_of_quantum_technologies_0.pdf](sediment://file_00000000c67461f6b084a086ce34ccc0)
  - **Satellite / free-space QKD** for cross-region links (weather and ops constraints).
  - **Future entanglement-based networks** (second-generation): requires repeaters/quantum memory.

- Recommended operational pattern:
  1. Use PQC KEM in all cases to derive an initial shared secret.
  2. If QKD is available, obtain a QKD key (keyID) and combine via HKDF(shared_secret || QKD_key || QRNG_output) to derive the session AEAD key.
  3. For non-QKD links, use PQC KEM + QRNG seed.

- Node hardening & evaluation: follow ISO/IEC 23837 for requirements and tests.  [oai_citation:15‡ISO](https://www.iso.org/standard/77097.html?utm_source=chatgpt.com)

================================================================================
FILE: docs/PQC_PLAN.md
================================================================================
# PQC migration plan (prototype + roadmap)

1. **Discovery (inventory)** — Enumerate endpoints, certs, keys and dependent systems.
2. **Pilot (hybrid)** — Implement hybrid key-establishment (classic X25519 + Kyber) for a narrow set of services, run interoperability tests and performance benchmarks.
3. **Rollout phases**:
   - Phase 1: Pilot / internal services (2026 target for pilots)
   - Phase 2: High-value production services (2030 milestones align w/ EU/NIST recommendations)
   - Phase 3: Full migration and deprecation of vulnerable primitives by 2035 (per NIST guidance).  [oai_citation:16‡NIST Computer Security Resource Center](https://csrc.nist.gov/csrc/media/Presentations/2025/nist-pqc-the-road-ahead/images-media/rwcpqc-march2025-moody.pdf?utm_source=chatgpt.com)

================================================================================
FILE: API_SPEC.md
================================================================================
# API_SPEC (security excerpt) — OpenAPI / conceptual

## Overview
This file contains a security scheme description for the experimental **QASP** (Quantum API Security Protocol) and an OpenAPI securityScheme snippet for integration.

## QASP handshake (conceptual sequence)
- Notation:
  - `Client` and `Server`.
  - `KEM(pub,priv)` = PQC KEM pair (e.g., Kyber).
  - `SIGN` = PQC signature (e.g., Dilithium).
  - `QKD_KEY_ID` = identifier of a QKD session key if available.

### 1) Client Registration
- Client registers `pub_kem` and `pub_sign` with server via out-of-band provisioning (or DOS-protected API). The registration is signed or provisioned via HSM attestation.

### 2) Session initiation (client -> server)

POST /qasp/init
Body:
{
“client_id”: “acme-client-42”,
“kem_encaps”: “”,
“supported_qkd”: true/false,
“nonce”: “<client_nonce>”
}

Server decapsulates `kem_encaps` with its `priv_kem` -> `shared_secret_kem`.
If QKD available and accepted, server returns `QKD_KEY_ID` and ephemeral server nonce.

### 3) Key derivation
Client and server derive session AEAD key:
`session_key = HKDF(shared_secret_kem || qkd_key(if present) || QRNG_output(if present) || client_nonce || server_nonce)`

### 4) Challenge / Verify
Server sends challenge MAC'd with `session_key`. Client responds with MAC and signs a transcript with its `priv_sign` (optional high-assurance step), server verifies.

**Security notes:**
- Signatures provide non-repudiation for client provisioning events.
- Ephemeral KEM per session gives forward secrecy; combining QKD/QRNG adds hardware-rooted entropy where available.
- All endpoints MUST accept PQC-signed registration and fallback to PQC KEM handshake if QKD is not available.

## OpenAPI securitySchemes (conceptual snippet)
```yaml
components:
  securitySchemes:
    QASP:
      type: apiKey
      in: header
      name: X-QASP-Session
      description: >
        Short opaque session token proving possession of a QASP-derived session key.
        Token is issued after a successful QASP handshake and is MAC'd with AEAD using session_key.
security:
 - QASP: []

================================================================================
FILE: specs/IMPLEMENTATION_GUIDE.md

Implementation guidance (prototype)
	•	Languages: start with Python (FastAPI) or Go (Fiber/Gin) for quick experiments.
	•	Crypto libs: use libraries that have PQC support (link to NIST list in docs). Example libs: liboqs bindings, pqcrypto wrappers. For production, use vetted FIPS-certified builds.
	•	HSM & KMS: integrate with an HSM that can store PQC keys or use a KMS that supports importing PQC keys.
	•	GUI/UX: provide a status dashboard to show QKD link states and KMS key IDs.

================================================================================
FILE: specs/OPERATIONAL_RUNBOOK.md

Runbook (initial)
	•	How to provision a client:
	1.	Generate PQC KEM keypair (Kyber).
	2.	Generate PQC signature keypair (Dilithium).
	3.	Register pub keys with server’s provision endpoint (signed or via admin).
	4.	Add ledger entry.
	•	Incident steps for suspected key compromise:
	1.	Revoke key in KMS, publish revocation in admin API.
	2.	Rotate KEM keys and re-establish QKD sessions where relevant.

================================================================================
FILE: vibe_ledger/VIBE_LEDGER.md

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
  commit: "<commit-sha>"
  notes: "Use HSM for private key storage; pilot Kyber + Dilithium."

	•	New entries MUST include: id, date, actor, task, status, files_changed, commit, notes.

================================================================================
FILE: templates/ISSUE_TEMPLATE.md

Issue template (vibe)

Title: [short]
Type: bug / feature / security / doc / chore
Description:
Steps to reproduce (if bug):
Impact:
Suggested owner:
Ledger-entry-required: yes/no

================================================================================
FILE: templates/PULL_REQUEST_TEMPLATE.md

PR template (vibe)
	•	Summary of change:
	•	Files changed:
	•	Test plan:
	•	Security considerations (required):
	•	Add ledger entry? (yes/no)

================================================================================
FILE: ci/pipeline.yaml

CI skeleton (conceptual)
	•	jobs:
	•	lint
	•	unit-tests
	•	pqc-compat-check (run pqc integration tests / size/perf)
	•	security-scan
	•	deploy-staging

================================================================================
FILE: tests/SECURITY_TEST_PLAN.md

Security test plan (quantum-focused)
	•	Test PQC KEM handshake for interoperability with chosen libraries.
	•	Emulate harvest-now scenario: intercept and attempt to recover session keys if PQC or KEM are weak (black-box tests).
	•	QKD integration smoke tests: verify QKD_KEY_ID flow and key mixing semantics.
	•	Side-channel checks for QRNG and QKD modules (if hardware available).

================================================================================
FILE: src/app_stub.py

App skeleton (placeholder)

“””
This file is the minimal app skeleton that references QASP handshake endpoints.
Real crypto calls should call into vetted libs & HSMs.
“””

================================================================================
FILE: LICENSE

MIT License
(c) {{YEAR}} {{OWNER}}

================================================================================
COMMIT + BRANCH rules (to apply after file creation)
	1.	Commit all created files in one commit chore:init-templates.
	2.	Create branch vibe/init and push into remote (if remote configured).
	3.	Append a ledger entry with id 0001 as shown in the VIBE_LEDGER seed.

================================================================================
Operational notes for CLIne when producing files:
	•	Replace {{YEAR}} and {{OWNER}} with repository metadata CLIne can ask for if desired; if CLIne must not ask, use the defaults: YEAR=2025 OWNER=“QuantumSecureTeam”.
	•	When writing files referencing standards, include a references block with the following citations:
	•	SIPRI primer (attached) — used as inspiration for QKD trade-offs.  ￼
	•	NIST PQC pages and standards (CRYSTALS-Kyber / CRYSTALS-Dilithium) — guidance for PQC baseline.  ￼
	•	NIST PQC timeline & migration recommendations (deprecation targets).  ￼
	•	ISO/IEC 23837 QKD baseline & testing guidance.  ￼
	•	ENISA PQC catalogue & guidance.  ￼
	•	ITU/ITU-T security requirements for QKD nodes.  ￼

================================================================================
End of master prompt.
