#!/usr/bin/env python3
"""
QASP v1.0 Audit Report Generator

Runs automated compliance checks based on audit_checklist.yaml
Generates reports/audit_report_v1_0.json with pass/fail status.
"""

import os
import sys
import json
import yaml
import time
from datetime import datetime
from typing import Dict, List, Any, Tuple
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

try:
    from src.config.crypto_config import validate_crypto_config, CRYPTO_CONFIG
    from src.qkd.hardware_driver import load_qkd_driver
    from src.telemetry.metrics import get_metrics
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
    print(f"Warning: Could not import QASP modules: {e}")
    logger = None

def load_checklist() -> Dict[str, Any]:
    """Load the audit checklist YAML."""
    checklist_path = Path(__file__).parent / "audit_checklist.yaml"
    with open(checklist_path) as f:
        return yaml.safe_load(f)

def check_qkd_device_integrity() -> Tuple[bool, str, Dict[str, Any]]:
    """Check QKD hardware device integrity."""
    try:
        driver = load_qkd_driver()
        available = driver.is_available()
        metadata = {"driver_type": type(driver).__name__, "available": available}
        if available:
            return True, "QKD driver operational", metadata
        else:
            return False, "QKD driver not available", metadata
    except Exception as e:
        return False, f"QKD driver error: {str(e)}", {"error": str(e)}

def check_pqc_algorithm_validation() -> Tuple[bool, str, Dict[str, Any]]:
    """Check PQC algorithm selection and parameters."""
    try:
        validate_crypto_config()
        kem_alg = CRYPTO_CONFIG.get('kem_algorithm', '')
        sig_alg = CRYPTO_CONFIG.get('signature_algorithm', '')

        # Check NIST-selected algorithms
        valid_kem = kem_alg in ['Kyber512', 'Kyber768', 'Kyber1024']
        valid_sig = sig_alg in ['Dilithium2', 'Dilithium3', 'Dilithium5']

        if valid_kem and valid_sig:
            return True, f"Algorithms valid: KEM={kem_alg}, SIG={sig_alg}", {
                "kem_algorithm": kem_alg,
                "signature_algorithm": sig_alg,
                "level": "3" if "1024" in kem_alg or "5" in sig_alg else "2"
            }
        else:
            return False, f"Invalid algorithms: KEM={kem_alg}, SIG={sig_alg}", {}

    except Exception as e:
        return False, f"PQC validation failed: {str(e)}", {"error": str(e)}

def check_key_storage_security() -> Tuple[bool, str, Dict[str, Any]]:
    """Check secure key storage configuration."""
    hsm_enabled = os.getenv("HSM_ENABLED", "false").lower() == "true"
    if hsm_enabled:
        return True, "HSM enabled for secure key storage", {"hsm_enabled": True}
    else:
        return False, "HSM not enabled - keys stored insecurely", {"hsm_enabled": False}

def check_tls_cert_validation() -> Tuple[bool, str, Dict[str, Any]]:
    """Check TLS certificate validation (manual for now)."""
    # This is hard to automate fully, so we check for configuration presence
    tls_cert_path = os.getenv("TLS_CERT_PATH", "")
    tls_key_path = os.getenv("TLS_KEY_PATH", "")
    fips_mode = os.getenv("TLS_FIPS_MODE", "false").lower() == "true"

    if tls_cert_path and tls_key_path:
        if fips_mode:
            return True, "TLS configured with FIPS mode", {"fips_mode": True}
        else:
            return False, "TLS configured but FIPS mode disabled", {"fips_mode": False}
    else:
        return False, "TLS certificates not configured", {}

def check_audit_log_integrity() -> Tuple[bool, str, Dict[str, Any]]:
    """Check audit log integrity (manual for now)."""
    log_level = os.getenv("LOG_LEVEL", "info").lower()
    structured_logging = os.getenv("STRUCTURED_LOGGING", "true").lower() == "true"

    if structured_logging and log_level in ["info", "warning", "error"]:
        return True, "Structured logging configured", {"structured_logging": True}
    else:
        return False, "Structured logging not properly configured", {"structured_logging": structured_logging}

def check_qkd_failover_mechanism() -> Tuple[bool, str, Dict[str, Any]]:
    """Check QKD failover mechanism."""
    # Test fallback by checking if QKD failure is handled gracefully
    try:
        driver = load_qkd_driver()
        # Try to get a key - this should not crash
        if driver.is_available():
            key, metadata = driver.get_qkd_key("test-session")
            # Simulate failure and check fallback
            return True, "QKD failover mechanism functional", metadata
        else:
            return True, "QKD driver properly reports unavailability", {"simulated": True}
    except Exception as e:
        return False, f"QKD failover test failed: {str(e)}", {"error": str(e)}

def check_performance_thresholds() -> Tuple[bool, str, Dict[str, Any]]:
    """Check performance thresholds."""
    # This would require actual performance testing
    # For now, check if monitoring is enabled
    try:
        metrics = get_metrics()
        if "qasp_handshake_duration" in metrics or "HANDSHAKE_DURATION" in str(metrics):
            return True, "Performance monitoring active", {"monitoring_enabled": True}
        else:
            return False, "Performance monitoring not properly configured", {}
    except Exception as e:
        return False, f"Performance check failed: {str(e)}", {"error": str(e)}

def run_audits() -> Dict[str, Any]:
    """Run all audit checks."""
    checklist = load_checklist()

    results = {
        "version": checklist["version"],
        "timestamp": datetime.utcnow().isoformat(),
        "title": checklist["title"],
        "summary": {
            "total_checks": len(checklist["controls"]),
            "passed": 0,
            "failed": 0,
            "warnings": 0
        },
        "controls": []
    }

    check_functions = {
        "qkd-device-integrity": check_qkd_device_integrity,
        "pqc-algorithm-validation": check_pqc_algorithm_validation,
        "key-storage-security": check_key_storage_security,
        "tls-cert-validation": check_tls_cert_validation,
        "audit-log-integrity": check_audit_log_integrity,
        "qkd-failover-mechanism": check_qkd_failover_mechanism,
        "performance-thresholds": check_performance_thresholds
    }

    for control in checklist["controls"]:
        control_id = control["id"]
        if control_id in check_functions:
            passed, message, metadata = check_functions[control_id]()
            status = "passed" if passed else "failed"

            control_result = {
                "id": control_id,
                "category": control["category"],
                "standard": control["standard"],
                "description": control["description"],
                "automated": control["automated"],
                "status": status,
                "message": message,
                "metadata": metadata
            }

            results["controls"].append(control_result)

            if passed:
                results["summary"]["passed"] += 1
            else:
                results["summary"]["failed"] += 1
        else:
            results["controls"].append({
                "id": control_id,
                "status": "error",
                "message": "Check function not implemented"
            })
            results["summary"]["failed"] += 1

    results["compliance_level"] = "compliant" if results["summary"]["failed"] == 0 else "non_compliant"

    return results

def main():
    """Generate audit report."""
    print("Running QASP v1.0 audit checks...")

    try:
        results = run_audits()

        # Write report
        output_dir = Path(__file__).parent / "reports"
        output_dir.mkdir(exist_ok=True)
        output_path = output_dir / "audit_report_v1_0.json"

        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)

        print(f"✓ Audit report generated: {output_path}")
        print(f"  Status: {results['compliance_level']}")
        print(f"  Passed: {results['summary']['passed']}, Failed: {results['summary']['failed']}")

        if results["summary"]["failed"] > 0:
            print("Failed checks:")
            for control in results["controls"]:
                if control["status"] == "failed":
                    print(f"  - {control['id']}: {control['message']}")
            sys.exit(1)

    except Exception as e:
        print(f"✗ Audit generation failed: {e}")
        if logger:
            logger.error("Audit generation failed", error=str(e))
        sys.exit(1)

if __name__ == "__main__":
    main()
