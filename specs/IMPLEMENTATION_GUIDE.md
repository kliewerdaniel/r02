Implementation guidance (prototype)
•	Languages: start with Python (FastAPI) or Go (Fiber/Gin) for quick experiments.
•	Crypto libs: use libraries that have PQC support (link to NIST list in docs). Example libs: liboqs bindings, pqcrypto wrappers. For production, use vetted FIPS-certified builds.
•	HSM & KMS: integrate with an HSM that can store PQC keys or use a KMS that supports importing PQC keys.
•	GUI/UX: provide a status dashboard to show QKD link states and KMS key IDs.
