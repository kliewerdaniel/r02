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
