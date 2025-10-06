#!/usr/bin/env python3
"""
QASP v1.0 Stress Performance Testing Tool

Simulates high-concurrency handshake operations to stress-test QASP v1.0 servers.
Generates performance reports and Grafana-ready metrics export.
"""

import asyncio
import base64
import httpx
import os
import json
import time
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from pathlib import Path
import statistics
import concurrent.futures

# Add src to path
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

try:
    from qasp.crypto import PQCKEM, PQCSign, derive_session_key, aead_encrypt, aead_decrypt
    from interop.qasp_interop import serialize_handshake
    import structlog
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer()
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
    logger = structlog.get_logger(__name__)
except ImportError as e:
    logger = None
    print(f"Warning: Could not import QASP modules: {e}")

@dataclass
class PerformanceMetrics:
    """Container for performance test results."""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    avg_latency_ms: float = 0.0
    median_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    p99_latency_ms: float = 0.0
    min_latency_ms: float = float('inf')
    max_latency_ms: float = 0.0
    requests_per_second: float = 0.0
    error_rate: float = 0.0
    test_duration_seconds: float = 0.0
    start_time: str = ""
    end_time: str = ""
    latencies: List[float] = None

    def __post_init__(self):
        if self.latencies is None:
            self.latencies = []

    def add_latency(self, latency_ms: float):
        """Add a latency measurement."""
        self.latencies.append(latency_ms)
        self.min_latency_ms = min(self.min_latency_ms, latency_ms)
        self.max_latency_ms = max(self.max_latency_ms, latency_ms)

    def calculate_stats(self):
        """Calculate statistical metrics from collected latencies."""
        if self.latencies:
            self.avg_latency_ms = statistics.mean(self.latencies)
            self.median_latency_ms = statistics.median(self.latencies)
            self.p95_latency_ms = statistics.quantiles(self.latencies, n=20)[18]  # 95th percentile
            self.p99_latency_ms = statistics.quantiles(self.latencies, n=100)[98]  # 99th percentile
        else:
            self.avg_latency_ms = self.median_latency_ms = self.p95_latency_ms = self.p99_latency_ms = 0.0

        total_requests = self.successful_requests + self.failed_requests
        if total_requests > 0:
            self.error_rate = (self.failed_requests / total_requests) * 100
        if self.test_duration_seconds > 0:
            self.requests_per_second = total_requests / self.test_duration_seconds

class AsyncQASPClient:
    """Async QASP client for load testing."""

    def __init__(self, server_url: str, client_id: str, tenant_id: str = "load-test"):
        self.server_url = server_url.rstrip('/')
        self.client_id = client_id
        self.tenant_id = tenant_id
        self.session_timeout = 300  # 5 minutes

        # Pre-generate keys for performance
        try:
            self.kem = PQCKEM(tenant_id=self.tenant_id)
            self.kem.generate_keypair()
            self.sign = PQCSign(tenant_id=self.tenant_id)
            self.sign.generate_keypair()
        except Exception:
            # Fallback for basic HTTP testing
            self.kem = None
            self.sign = None

    async def register_and_handshake(self, use_qkd: bool = False) -> tuple[float, bool, Optional[str]]:
        """
        Perform full register -> handshake operation.

        Returns:
            Tuple of (latency_ms, success, error_message)
        """
        start_time = time.time()

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                # Register client
                if self.kem and self.sign:
                    register_data = {
                        "client_id": self.client_id,
                        "tenant_id": self.tenant_id,
                        "pub_kem": base64.b64encode(self.kem.export_public()).decode(),
                        "pub_sig": base64.b64encode(self.sign.export_public()).decode()
                    }

                    reg_response = await client.post(f"{self.server_url}/qasp/register", json=register_data)
                    reg_response.raise_for_status()

                # Get server keys
                key_response = await client.get(f"{self.server_url}/public-keys")
                key_response.raise_for_status()
                server_keys = key_response.json()

                # Perform handshake
                client_nonce = os.urandom(16)

                if self.kem:
                    server_kem_pub = base64.b64decode(server_keys["pub_kem"])
                    ciphertext, shared_secret = self.kem.encapsulate(server_kem_pub)
                    kem_encaps_b64 = base64.b64encode(ciphertext).decode()
                else:
                    # Fallback to mock data for HTTP testing
                    shared_secret = os.urandom(32)
                    kem_encaps_b64 = base64.b64encode(os.urandom(32)).decode()

                handshake_data = {
                    "client_id": self.client_id,
                    "tenant_id": self.tenant_id,
                    "kem_encaps": kem_encaps_b64,
                    "client_nonce": base64.b64encode(client_nonce).decode(),
                    "supported_qkd": use_qkd
                }

                if self.kem:
                    serialized = serialize_handshake(handshake_data)
                    content = serialized
                    headers = {"Content-Type": "application/json"}
                else:
                    content = json.dumps(handshake_data)
                    headers = {"Content-Type": "application/json"}

                hs_response = await client.post(
                    f"{self.server_url}/qasp/init",
                    content=content,
                    headers=headers
                )
                hs_response.raise_for_status()

                # Extract result
                result = hs_response.json()
                server_nonce = base64.b64decode(result["server_nonce"])
                session_token = result["session_token"]

                # Derive session key (optional validation)
                qkd_key = None
                session_key = derive_session_key(shared_secret, qkd_key, None, client_nonce, server_nonce)

                end_time = time.time()
                latency_ms = (end_time - start_time) * 1000

                return latency_ms, True, None

        except Exception as e:
            end_time = time.time()
            latency_ms = (end_time - start_time) * 1000
            return latency_ms, False, str(e)

async def run_single_client(client: AsyncQASPClient, metrics: PerformanceMetrics, use_qkd: bool) -> None:
    """Run a single client's handshake operation."""
    latency, success, error = await client.register_and_handshake(use_qkd)

    metrics.add_latency(latency)

    if success:
        metrics.successful_requests += 1
    else:
        metrics.failed_requests += 1

        if logger:
            logger.warning("Handshake failed", client_id=client.client_id, error=error)

async def run_concurrent_test(server_url: str, num_clients: int = 1000, use_qkd: bool = False, max_concurrent: int = 100) -> PerformanceMetrics:
    """Run concurrent handshake load test."""
    metrics = PerformanceMetrics()
    metrics.start_time = datetime.utcnow().isoformat()
    metrics.total_requests = num_clients

    start_time = time.time()

    # Create semaphore to limit concurrent clients
    semaphore = asyncio.Semaphore(max_concurrent)

    async def limited_handshake(client: AsyncQASPClient):
        async with semaphore:
            await run_single_client(client, metrics, use_qkd)

    # Create clients
    clients = [
        AsyncQASPClient(server_url, f"load-client-{i:04d}", f"tenant-{i % 10}")
        for i in range(num_clients)
    ]

    # Run all handshakes concurrently (within limits)
    tasks = [limited_handshake(client) for client in clients]

    # Run in batches to avoid overwhelming the event loop
    batch_size = 500
    for i in range(0, len(tasks), batch_size):
        batch = tasks[i:i + batch_size]
        await asyncio.gather(*batch, return_exceptions=True)

    end_time = time.time()
    metrics.test_duration_seconds = end_time - start_time
    metrics.end_time = datetime.utcnow().isoformat()
    metrics.calculate_stats()

    return metrics

def generate_grafana_export(metrics: PerformanceMetrics) -> Dict[str, Any]:
    """Generate Grafana-ready metrics export."""
    return {
        "annotations": {
            "list": []
        },
        "time": {
            "from": metrics.start_time,
            "to": metrics.end_time
        },
        "timeRange": {
            "from": metrics.start_time,
            "to": metrics.end_time
        },
        "targets": [
            {
                "target": "qasp_handshake_duration_seconds",
                "type": "timeserie"
            }
        ],
        "panels": [
            {
                "title": "QASP v1.0 Stress Test Results",
                "type": "table",
                "targets": [
                    {
                        "expr": "qasp_handshake_duration_seconds",
                        "legendFormat": "Handshake Duration"
                    }
                ],
                "fieldConfig": {
                    "defaults": {
                        "mappings": [],
                        "thresholds": {
                            "mode": "absolute",
                            "steps": [
                                {"color": "green", "value": None},
                                {"color": "red", "value": 500}
                            ]
                        }
                    }
                }
            }
        ],
        "refresh": False,
        "schemaVersion": 27,
        "style": "dark",
        "tags": ["qasp", "performance", "stress-test"],
        "templating": {
            "list": []
        },
        "timePicker": {},
        "timeZone": "",
        "title": "QASP v1.0 Stress Test Results",
        "uid": f"qasp-stress-{int(time.time())}",
        "version": 1
    }

def main():
    """Run QASP stress performance testing."""
    import argparse

    parser = argparse.ArgumentParser(description="QASP v1.0 Stress Performance Testing")
    parser.add_argument("--server-url", default="http://localhost:8000", help="QASP server URL")
    parser.add_argument("--clients", type=int, default=1000, help="Number of concurrent clients")
    parser.add_argument("--max-concurrent", type=int, default=100, help="Maximum concurrent requests")
    parser.add_argument("--use-qkd", action="store_true", help="Enable QKD in handshakes")
    parser.add_argument("--output-dir", default="reports", help="Output directory for reports")

    args = parser.parse_args()

    print("QASP v1.0 Stress Performance Test")
    print("=" * 40)
    print(f"Server URL: {args.server_url}")
    print(f"Concurrent clients: {args.clients}")
    print(f"Max concurrent: {args.max_concurrent}")
    print(f"QKD enabled: {args.use_qkd}")
    print()

    start_time = time.time()

    try:
        # Run the stress test
        metrics = asyncio.run(run_concurrent_test(
            args.server_url,
            args.clients,
            args.use_qkd,
            args.max_concurrent
        ))

        end_time = time.time()
        total_time = end_time - start_time

        print("Performance Results:")
        print("-" * 20)
        print(f"Total requests: {metrics.total_requests}")
        print(f"Successful: {metrics.successful_requests}")
        print(f"Failed: {metrics.failed_requests}")
        print(f"Avg latency: {metrics.avg_latency_ms:.2f}ms")
        print(f"Median latency: {metrics.median_latency_ms:.2f}ms")
        print(f"95th percentile: {metrics.p95_latency_ms:.2f}ms")
        print(f"99th percentile: {metrics.p99_latency_ms:.2f}ms")
        print(f"Min latency: {metrics.min_latency_ms:.2f}ms")
        print(f"Max latency: {metrics.max_latency_ms:.2f}ms")
        print(f"Requests/sec: {metrics.requests_per_second:.3f}")
        print(f"Test duration: {metrics.test_duration_seconds:.3f}s")
        print()

        print("Acceptance Criteria:")
        print("-" * 20)

        # Check acceptance criteria from requirements
        criteria_passed = True

        # Latency ≤ 500ms avg
        if metrics.avg_latency_ms <= 500:
            print("✓ Average latency ≤ 500ms")
        else:
            print(f"✗ Average latency > 500ms ({metrics.avg_latency_ms:.2f}ms)")
            criteria_passed = False

        # Error rate < 0.5%
        if metrics.error_rate < 0.5:
            print("✓ Error rate < 0.5%")
        else:
            print(f"✗ Error rate > 0.5% ({metrics.error_rate:.2f}%)")
            criteria_passed = False

        # Generate reports
        output_dir = Path(args.output_dir)
        output_dir.mkdir(exist_ok=True)

        # JSON report
        report_path = output_dir / "perf_v1_0_stable.json"
        report_data = {
            "version": "1.0",
            "test_type": "stress_performance",
            "timestamp": datetime.utcnow().isoformat(),
            "configuration": {
                "server_url": args.server_url,
                "num_clients": args.clients,
                "max_concurrent": args.max_concurrent,
                "use_qkd": args.use_qkd
            },
            "metrics": asdict(metrics),
            "acceptance_criteria": {
                "latency_threshold_ms": 500,
                "error_rate_threshold_percent": 0.5,
                "overall_pass": criteria_passed
            }
        }

        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)

        print(f"✓ Performance report saved: {report_path}")

        # Grafana export
        grafana_path = output_dir / "grafana_perf_export.json"
        grafana_data = generate_grafana_export(metrics)

        with open(grafana_path, 'w') as f:
            json.dump(grafana_data, f, indent=2, default=str)

        print(f"✓ Grafana export saved: {grafana_path}")

        if criteria_passed:
            print("\n🎉 All acceptance criteria passed!")
            return 0
        else:
            print("\n❌ Acceptance criteria not met.")
            return 1

    except Exception as e:
        print(f"✗ Test failed: {e}")
        if logger:
            logger.error("Stress test failed", error=str(e))
        return 1

if __name__ == "__main__":
    exit(main())
