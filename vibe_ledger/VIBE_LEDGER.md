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

•	New entries MUST include: id, date, actor, task, status, files_changed, commit, notes.
