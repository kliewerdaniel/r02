

=== CLIne ACTION PROMPT: Start Development — QuantumSecureAPI (vibe/dev/initial-implementation) ===

Context:
You (CLIne) already created the template skeleton (README.md, API_SPEC.md, docs/, vibe_ledger/, templates/, ci/ etc.). Now start development: implement a prototype QASP v0.1 server+client (FastAPI) that performs a PQC KEM+signature handshake, derives a session AEAD key combining KEM shared-secret + optional QKD/QRNG material, and uses that session key to protect API calls. Use liboqs (Open Quantum Safe) Python bindings for PQC experiments. Use the SIPRI primer (attached) as design inspiration for QKD tradeoffs and mention it in the doc changes.  [oai_citation:1‡0725_military_and_security_dimensions_of_quantum_technologies_0.pdf](sediment://file_00000000c67461f6b084a086ce34ccc0)

Top-level objectives (do them in this order):
1. Create branch `vibe/dev/initial-implementation`.
2. Create a working dev environment (python venv & Dockerfile).
3. Implement core crypto wrappers (liboqs wrappers + HKDF + AEAD).
4. Implement QASP handshake endpoints on a minimal FastAPI server.
5. Implement a minimal client that performs the handshake and calls a protected endpoint.
6. Implement a mock QKD service for prototype testing (REST + in-memory key store).
7. Add unit & integration tests (pytest) and a CI job that runs tests and a PQC compatibility smoke test.
8. Update `vibe_ledger/VIBE_LEDGER.md` at each major commit and append ledger entries after each milestone.
9. Create GitHub issues for the remaining backlog and tag them to `vibe/sprint-1` milestone.
10. Produce a short demo runbook (how to run locally + how to demo handshake).

Authoritative references CLIne must use for PQC tooling & installation:
- NIST PQC selections & guidance (use for algorithm choices: Kyber for KEM, Dilithium for signatures).  [oai_citation:2‡NIST](https://www.nist.gov/news-events/news/2022/07/pqc-standardization-process-announcing-four-candidates-be-standardized-plus?utm_source=chatgpt.com)  
- Open Quantum Safe / liboqs + Python bindings (install & example usage). Use the examples/kem.py and examples/sig.py as canonical references for the wrapper API. **Important:** liboqs is intended for prototyping. Treat it as a research/prototyping dependency, not a production HSM.  [oai_citation:3‡GitHub](https://github.com/open-quantum-safe/liboqs-python)  
- OQS Provider for OpenSSL (if later integrating TLS).  [oai_citation:4‡GitHub](https://github.com/open-quantum-safe/oqs-provider?utm_source=chatgpt.com)

Branch/commit policy for this run:
- Create branch: `vibe/dev/initial-implementation`.
- Commit granularity: group related changes into small commits. Every commit that changes source or infra MUST append a ledger entry (see section below).
- Initial commit message: `feat(qasp): initial implementation skeleton + pqc wrappers`
- After finishing the run, open a PR `vibe/dev/initial-implementation -> main` with PR template filled (security considerations required).

Concrete tasks & files to create (paths relative to repo root).
(Instruction: create the file(s) with the skeleton contents described below; if files already exist, update them and append a ledger entry.)

A. Environment & infra
- Create `requirements.txt`:

fastapi
uvicorn[standard]
pydantic
cryptography
pytest
pytest-asyncio
aiohttp
oqs              # liboqs-python or wrapper; ensure build steps exist in Dockerfile

NOTE: installing `oqs` may build liboqs from source; use the liboqs-python documented install flow. See liboqs-python examples.  [oai_citation:5‡GitHub](https://github.com/open-quantum-safe/liboqs-python)

- Create `Dockerfile` (dev): base python:3.11-slim, install build deps (cmake, gcc, make) and run `pip install .` in a small oqs-wrapper dir OR rely on liboqs-python automation per examples. Add a `make dev` target that builds the image and runs the server for local demos.

B. Core crypto wrappers — `src/qasp/crypto.py`
- Purpose: isolate every crypto decision here so later we can swap libs/HSMs.
- Exported API:
- `class PQCKEM`: `generate_keypair() -> public_bytes`, `encapsulate(peer_pub) -> (ciphertext, shared_secret)`, `decapsulate(ciphertext) -> shared_secret`, `export_public()`.
- `class PQCSign`: `generate_keypair()`, `sign(message)`, `verify(pub, message, sig)`.
- `def derive_session_key(shared_secret: bytes, qkd_key: Optional[bytes], qrng: Optional[bytes], client_nonce: bytes, server_nonce: bytes) -> bytes` — use HKDF(SHA-256) to derive 32 bytes.
- `def aead_encrypt(key, plaintext, aad) -> (nonce, ciphertext)`, `def aead_decrypt(key, nonce, ciphertext, aad)`.
- Implementation notes:
- Use `oqs` wrapper for KEM + signature objects (examples in liboqs-python). See repo examples for exact method names and adapt.  [oai_citation:6‡GitHub](https://github.com/open-quantum-safe/liboqs-python)
- For AEAD, use `cryptography.hazmat.primitives.ciphers.aead.XChaCha20Poly1305` if available, else AES-GCM fallback.
- For HKDF use `cryptography.hazmat.primitives.kdf.hkdf.HKDF` with SHA-256 and include contextual info (protocol version, client/server IDs) in info.

C. QKD mock & QRNG shim — `src/qkd/mock_qkd.py`
- Provide two modes: `sim` (returns strong os.urandom bytes) and `mock-hardware` (deterministic pseudo to enable reproducible tests).
- REST shim: `GET /qkd/session` returns `{ "qkd_key_id": "<uuid>", "qkd_key": base64(...) }` — in production this would be replaced by a hardware provider API.
- Instruction: DO NOT persist raw qkd_key to disk in plain text; for prototype, store in memory and mark logs as sensitive.

D. Server — `src/server/main.py` (FastAPI)
- Endpoints to implement:
- `POST /qasp/register` — admin-only: register client `client_id` and store pub_kem + pub_sig (simulate out-of-band registration).
- `POST /qasp/init` — client sends `client_id`, `kem_encaps` (bytes, base64), `client_nonce`, `supported_qkd: bool`. Server decapsulates to get `shared_secret_kem`, optionally call QKD service to get `qkd_key`, derive session_key, create short opaque session token that is AEAD(mac'd) using session_key (token contains session_id, expiry), return `server_nonce` and `session_token`.
- `POST /qasp/challenge` — server verifies session token and challenge to confirm possession of session_key.
- `GET /protected/resource` — requires `X-QASP-Session: <session_token>` header and demonstrates decrypting/validating a payload.
- Put clear TODOs where HSM/KMS integration would plug in (e.g., `store_priv_kem_in_hsm()`).

E. Client — `src/client/demo_client.py`
- Implement a CLI/demo client that:
1. Generates ephemeral kem encapsulation for server pubkey (or uses registered client keypair, depending on flow).
2. Calls `/qasp/init`, receives `session_token`.
3. Calls `/protected/resource` with the session token in header and demonstrates decrypting response.

F. Tests — `tests/test_qasp_handshake.py`
- Unit tests:
- KEM keypair generation & encapsulation/decapsulation symmetry test using liboqs examples as guide.
- derive_session_key produces same value on both sides when `shared_secret_kem`, `qkd_key`, `client_nonce`, `server_nonce` are identical.
- Integration test:
- Start FastAPI server in test mode (in-memory) and run client demo to perform a full handshake and access resource. Use pytest-asyncio.
- Add a `tests/fixtures` script that runs the `liboqs-python/examples/` kem.py as a smoke-check if liboqs is present.

G. CI — `.github/workflows/ci.yml`
- Jobs:
- `lint`: flake/ruff etc.
- `unit-tests`: run `pip install -r requirements.txt` and run pytest.
- `pqc-compat-check`: install liboqs (or let liboqs-python auto install), run `python -m liboqs-python.examples.kem` or internal smoke test; fail fast if PQC libs cannot be built. Reference liboqs-python install docs for commands.  [oai_citation:7‡GitHub](https://github.com/open-quantum-safe/liboqs-python)
- `security-scan`: Snyk/Dependabot config stub.

H. Docs updates
- Update `docs/SECURITY.md` and `docs/QKD_DESIGN.md` with notes on how the runtime maps to HSM/KMS and how to swap in hardware QKD providers.
- Add a new doc `docs/DEV_RUNBOOK.md` with commands to:
- `make dev` build Docker + run server
- `make test` run pytest
- `make demo` run demo client against local dev server

I. Vibe Ledger entries (after key commits)
- After the initial commit add entry id `0002` with:

	•	id: 0002
date: 
actor: CLIne
task: “initial dev implementation: env, crypto wrappers, qkd mock, server/client, tests”
status: done
files_created: […]
decisions: [“Use liboqs-python for PQC prototyping”, “FastAPI for server”, “HKDF + XChaCha20-Poly1305 AEAD”]
commit: “”
notes: “liboqs is prototyping-only; production requires HSM & vendor validated libs.”

- For every subsequent feature, append a new ledger id.

Acceptance Criteria / Definition of Done (for this run):
- `vibe/dev/initial-implementation` branch exists and pushes to remote.
- `pip install -r requirements.txt` (inside venv or Docker container) succeeds on a Linux dev box with liboqs built by the container (or liboqs-python automatic build).
- `pytest` runs and the unit tests for KEM/derive_key/encrypt pass in CI.
- Demo client performs handshake with server, obtains session token, and successfully calls `GET /protected/resource`.
- `vibe_ledger/VIBE_LEDGER.md` contains the `0002` ledger entry referencing these changes.
- A PR was opened with security checklist filled, and a `pqc-compat-check` CI job that exercises liboqs examples is present.

Security & operations notes (must be adhered to):
- **Do not** store private keys in plaintext. Put clear TODOs to integrate HSM/KMS in `src/qasp/crypto.py`.
- For prototype, mock QKD keys are acceptable; label the mock clearly in docs and tests.
- **Warning:** liboqs and liboqs-python are prototyping toolchains — reference their docs and the NIST PQC guidance. Treat experimental outputs accordingly.  [oai_citation:8‡GitHub](https://github.com/open-quantum-safe/liboqs-python)

PR / Issue automation:
- After completing branch work, automatically:
- Create issues for follow-ups: `HSM integration`, `QKD hardware integration`, `external audit`, `production key lifecycle`.
- Tag each issue with `security`, `pqc`, `infra`, `docs` as appropriate.
- Open draft PR titled: `feat: implement QASP v0.1 prototype (pqc+qkd mock)` and link the ledger entry.

Developer tips / references to consult while implementing:
- Use liboqs-python examples and the Open Quantum Safe docs for exact API call patterns (KeyEncapsulation, Signature, generate_keypair, encap/decap examples).  [oai_citation:9‡GitHub](https://github.com/open-quantum-safe/liboqs-python)
- Follow NIST PQC recommendations for baseline algorithm choices (Kyber for KEM, Dilithium for signatures) and document the exact parameter sets chosen in `docs/PQC_PLAN.md`.  [oai_citation:10‡NIST](https://www.nist.gov/news-events/news/2022/07/pqc-standardization-process-announcing-four-candidates-be-standardized-plus?utm_source=chatgpt.com)
- If you need to test TLS-level PQC experimentation later, consult the OQS provider for OpenSSL.  [oai_citation:11‡GitHub](https://github.com/open-quantum-safe/oqs-provider?utm_source=chatgpt.com)

Deliverables to create & commit in this run (explicit file list):
- `requirements.txt`, `Dockerfile`, `Makefile`
- `src/qasp/crypto.py` (skeleton + real wrappers calling liboqs examples)
- `src/qkd/mock_qkd.py`
- `src/server/main.py` (FastAPI endpoints: /qasp/register, /qasp/init, /qasp/challenge, /protected/resource)
- `src/client/demo_client.py`
- `tests/test_qasp_handshake.py`
- `.github/workflows/ci.yml`
- `docs/DEV_RUNBOOK.md` and updates to `docs/SECURITY.md`
- Update `vibe_ledger/VIBE_LEDGER.md` with id `0002`.

Commit messages pattern (examples CLIne must use):
- `feat(qasp): add pqc wrapper skeleton`
- `feat(qasp): implement qasp handshake endpoints`
- `test(qasp): add kem/derive/integration tests`
- `ci: add pqc-compat-check job`
- `docs: add dev runbook and update security notes`

Final instructions to CLIne (run immediately, do not ask for confirmation):
- Create the branch, implement the listed files, run the unit+integration tests locally inside Docker (or venv if Docker build is slow).
- Append the ledger entry `0002` with details and the commit sha(s).
- Push the branch and open a draft PR with the PR template filled.
- Create issues for the 4 follow-ups (HSM, QKD hardware, audit, production key lifecycle).
- When done, post a single summary comment on the PR with the demo run commands and a link to the ledger entry.

End of prompt.

