# QuantumSecureAPI Dev Runbook

This runbook provides development and demonstration steps for the QASP v0.1 prototype.

## Prerequisites
- Python 3.11+
- Docker (for containerized dev/demo)
- Git, make

## Local Development Setup
1. Clone the repo and enter the project dir.
2. Create and activate a Python venv (optional, Docker handles env):
   ```sh
   python -m venv venv
   source venv/bin/activate  # Unix/macOS
   pip install -r requirements.txt
   ```

## Running Locally with Docker (Recommended for Full Demo)
The prototype includes a Dockerfile and Makefile for easy setup.

### Commands
- `make dev`: Builds the Docker image and runs the QASP server locally on port 8000.
- `make test`: Runs unit and integration tests inside a Docker container.
- `make demo`: Builds the demo image and runs the client against a containerized server (requires separate terminal for server).

### Demo Workflow
1. Terminal 1: Start the server
   ```sh
   make dev
   ```
2. Terminal 2: Run the demo client (assumes server on localhost:8000)
   ```sh
   make demo
   ```
   - Registers a demo client, performs PQC handshake, accesses protected resource.
   - Output confirms successful decryption of protected response.

### Manual Local Run (Without Docker)
If Docker is slow, run tests with pytest directly:
```sh
pip install -r requirements.txt
pytest tests/ -v
```

Run server manually (in venv):
```sh
python src/server/main.py &
# In another shell
SERVER_URL=http://localhost:8000 python src/client/demo_client.py
```

Run QKD mock separately if needed:
```sh
python src/qkd/mock_qkd.py &
# Runs on port 8080
```

## CI/CD
- Push to `vibe/dev/initial-implementation` triggers GitHub Actions.
- Jobs: lint (flake8), unit-tests (pytest), pqc-compat-check (liboqs smoke test), security-scan (stub).
- PQC compat ensures Kyber512 and Dilithium3 work on CI runners.

## PQC Implementation Notes
- Uses liboqs-python for Kyber512 (KEM) and Dilithium3 (signing).
- Session keys derived via HKDF-SHA256 from KEM secret ± optional QKD.
- AEAD: ChaCha20-Poly1305 preferred, AES-GCM fallback.

## Troubleshooting
- If `pip install oqs` fails, ensure cmake/gcc available (apt on Ubuntu).
- For macOS, liboqs-python installs via Homebrew dependencies.
- QKD mock defaults to random mode; set `QKD_MODE=mock-hardware` for deterministic tests.
