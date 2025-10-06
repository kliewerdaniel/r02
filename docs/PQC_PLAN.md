# PQC migration plan (prototype + roadmap)

1. **Discovery (inventory)** — Enumerate endpoints, certs, keys and dependent systems.
2. **Pilot (hybrid)** — Implement hybrid key-establishment (classic X25519 + Kyber) for a narrow set of services, run interoperability tests and performance benchmarks.
3. **Rollout phases**:
   - Phase 1: Pilot / internal services (2026 target for pilots)
   - Phase 2: High-value production services (2030 milestones align w/ EU/NIST recommendations)
   - Phase 3: Full migration and deprecation of vulnerable primitives by 2035 (per NIST guidance).  [oai_citation:16‡NIST Computer Security Resource Center](https://csrc.nist.gov/csrc/media/Presentations/2025/nist-pqc-the-road-ahead/images-media/rwcpqc-march2025-moody.pdf?utm_source=chatgpt.com)
