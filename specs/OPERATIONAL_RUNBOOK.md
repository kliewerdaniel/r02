Runbook (initial)
•	How to provision a client:
1.	Generate PQC KEM keypair (Kyber).
2.	Generate PQC signature keypair (Dilithium).
3.	Register pub keys with server’s provision endpoint (signed or via admin).
4.	Add ledger entry.
•	Incident steps for suspected key compromise:
1.	Revoke key in KMS, publish revocation in admin API.
2.	Rotate KEM keys and re-establish QKD sessions where relevant.
