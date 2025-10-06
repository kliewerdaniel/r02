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

•	New entries MUST include: id, date, actor, task, status, files_changed, commit, notes.
