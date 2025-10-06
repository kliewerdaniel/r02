FROM python:3.11-slim

# Install build dependencies for liboqs
RUN apt-get update && apt-get install -y \\
    cmake \\
    gcc \\
    make \\
    libssl-dev \\
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "src.server.main:app", "--host", "0.0.0.0", "--port", "8000"]
