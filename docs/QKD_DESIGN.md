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
