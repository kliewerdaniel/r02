Security test plan (quantum-focused)
•	Test PQC KEM handshake for interoperability with chosen libraries.
•	Emulate harvest-now scenario: intercept and attempt to recover session keys if PQC or KEM are weak (black-box tests).
•	QKD integration smoke tests: verify QKD_KEY_ID flow and key mixing semantics.
•	Side-channel checks for QRNG and QKD modules (if hardware available).
