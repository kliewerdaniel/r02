"""
QASP Resilience and Failover Mechanisms

Provides automatic failover from QKD hardware to PQC-only mode,
with comprehensive monitoring and alerting capabilities.
"""

import os
import time
import threading
from typing import Optional, Dict, Any, Callable
from enum import Enum
from src.qkd.hardware_driver import IQKDDriver
from src.telemetry.metrics import QKD_STATUS, QKD_FAILOVER_EVENTS, QKD_LATENCY
from src.telemetry.logging_config import get_logger
import structlog

logger = structlog.get_logger(__name__)

class QKDHealthStatus(Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILED = "failed"
    UNKNOWN = "unknown"

class QKDFailoverManager:
    """
    Manages QKD hardware failover and PQC fallback mechanisms.

    Monitors QKD driver health and automatically switches to PQC-only mode
    when QKD hardware becomes unavailable or degraded.
    """

    def __init__(self, qkd_driver: IQKDDriver, health_check_interval: int = 30):
        """
        Initialize the failover manager.

        Args:
            qkd_driver: The QKD driver to monitor
            health_check_interval: Health check interval in seconds
        """
        self.qkd_driver = qkd_driver
        self.health_check_interval = health_check_interval
        self.last_health_check = 0
        self.current_status = QKDHealthStatus.UNKNOWN
        self.consecutive_failures = 0
        self.failover_threshold = int(os.getenv("QKD_FAILOVER_THRESHOLD", "3"))
        self.failover_enabled = os.getenv("QKD_FAILOVER_ENABLED", "true").lower() == "true"
        self.alert_callbacks: list[Callable[[QKDHealthStatus, QKDHealthStatus, Dict[str, Any]], None]] = []

        # Threading for health monitoring
        self.monitor_thread: Optional[threading.Thread] = None
        self.monitor_stop = threading.Event()

        # Initialize metrics
        self._init_metrics()

        logger.info("QKD Failover Manager initialized",
                   failover_enabled=self.failover_enabled,
                   threshold=self.failover_threshold,
                   interval=health_check_interval)

    def _init_metrics(self):
        """Initialize Prometheus metrics for QKD status."""
        # Metrics setup - assuming prometheus_client usage in metrics.py
        pass  # Metrics are defined in telemetry/metrics.py

    def add_alert_callback(self, callback: Callable[[QKDHealthStatus, QKDHealthStatus, Dict[str, Any]], None]):
        """Add a callback to be called on status changes."""
        self.alert_callbacks.append(callback)

    def _check_qkd_health(self) -> tuple[QKDHealthStatus, Dict[str, Any]]:
        """
        Perform health check on QKD driver.

        Returns:
            Tuple of (status, metadata_dict)
        """
        try:
            # Check if driver is available
            if not self.qkd_driver.is_available():
                return QKDHealthStatus.FAILED, {"error": "driver_not_available", "available": False}

            # Perform a test key retrieval to check latency and functionality
            start_time = time.time()
            test_key, metadata = self.qkd_driver.get_qkd_key(f"health-check-{int(time.time())}")
            latency_ms = (time.time() - start_time) * 1000

            # Update latency metric
            QKD_LATENCY.observe(latency_ms / 1000)  # Convert to seconds for Prometheus

            # Check latency thresholds
            max_latency_ms = float(os.getenv("QKD_MAX_LATENCY_MS", "100"))
            if latency_ms > max_latency_ms:
                return QKDHealthStatus.DEGRADED, {
                    **metadata,
                    "latency_ms": latency_ms,
                    "threshold_ms": max_latency_ms,
                    "error": "latency_threshold_exceeded"
                }

            return QKDHealthStatus.HEALTHY, {**metadata, "latency_ms": latency_ms}

        except Exception as e:
            logger.warning("QKD health check failed", error=str(e))
            return QKDHealthStatus.FAILED, {"error": str(e), "exception_type": type(e).__name__}

    def update_status(self, new_status: QKDHealthStatus, metadata: Dict[str, Any]):
        """Update QKD status and trigger alerts if status changed."""
        old_status = self.current_status
        self.current_status = new_status

        # Update Prometheus metrics
        if new_status == QKDHealthStatus.HEALTHY:
            QKD_STATUS.state('healthy')
            self.consecutive_failures = 0
        elif new_status == QKDHealthStatus.DEGRADED:
            QKD_STATUS.state('degraded')
            self.consecutive_failures = min(self.consecutive_failures + 1, 10)  # Cap at 10
        elif new_status == QKDHealthStatus.FAILED:
            QKD_STATUS.state('failed')
            self.consecutive_failures += 1
            QKD_FAILOVER_EVENTS.labels(reason='health_check_failure').inc()

        # Log status change
        if old_status != new_status:
            logger.info("QKD status changed",
                       old_status=old_status.value,
                       new_status=new_status.value,
                       metadata=metadata,
                       consecutive_failures=self.consecutive_failures)

            # Trigger alerts
            for callback in self.alert_callbacks:
                try:
                    callback(old_status, new_status, metadata)
                except Exception as e:
                    logger.error("Alert callback failed", error=str(e), callback=str(callback))

    def _health_monitor_loop(self):
        """Background thread for continuous health monitoring."""
        logger.info("Starting QKD health monitoring loop")

        while not self.monitor_stop.is_set():
            try:
                status, metadata = self._check_qkd_health()
                self.update_status(status, metadata)
                self.last_health_check = time.time()
            except Exception as e:
                logger.error("Health monitor loop error", error=str(e))

            self.monitor_stop.wait(self.health_check_interval)

        logger.info("QKD health monitoring loop stopped")

    def start_monitoring(self):
        """Start the health monitoring thread."""
        if self.monitor_thread is None or not self.monitor_thread.is_alive():
            self.monitor_thread = threading.Thread(
                target=self._health_monitor_loop,
                name="qkd-health-monitor",
                daemon=True
            )
            self.monitor_stop.clear()
            self.monitor_thread.start()
            logger.info("QKD health monitoring started")

    def stop_monitoring(self):
        """Stop the health monitoring thread."""
        if self.monitor_thread:
            logger.info("Stopping QKD health monitoring")
            self.monitor_stop.set()
            self.monitor_thread.join(timeout=5)
            if self.monitor_thread.is_alive():
                logger.warning("QKD health monitoring thread did not stop gracefully")

    def should_failover(self) -> bool:
        """
        Determine if failover to PQC-only mode should occur.

        Returns:
            True if system should failover, False otherwise
        """
        if not self.failover_enabled:
            return False

        # Failover if we've had too many consecutive failures or status is FAILED
        if self.consecutive_failures >= self.failover_threshold:
            return True

        if self.current_status == QKDHealthStatus.FAILED:
            return True

        return False

    def get_failover_status(self) -> Dict[str, Any]:
        """Get comprehensive failover status information."""
        return {
            "current_status": self.current_status.value,
            "consecutive_failures": self.consecutive_failures,
            "failover_threshold": self.failover_threshold,
            "failover_enabled": self.failover_enabled,
            "should_failover": self.should_failover(),
            "last_health_check": self.last_health_check,
            "time_since_last_check": time.time() - self.last_health_check
        }

class QKDFailoverDecorator:
    """
    Decorator that wraps QKD operations with failover logic.

    Automatically falls back to PQC-only mode when QKD is unavailable.
    """

    def __init__(self, failover_manager: QKDFailoverManager, pqc_fallback: Callable):
        """
        Initialize the failover decorator.

        Args:
            failover_manager: The QKD failover manager
            pqc_fallback: Function to call when QKD fails (should return key and empty metadata)
        """
        self.failover_manager = failover_manager
        self.pqc_fallback = pqc_fallback

    def get_secure_key(self, session_id: str) -> tuple[bytes, Dict[str, Any], bool]:
        """
        Get a secure key, falling back to PQC-only if QKD fails.

        Returns:
            Tuple of (key_bytes, metadata_dict, used_qkd)
        """
        if not self.failover_manager.should_failover():
            try:
                # Try QKD first
                key, metadata = self.failover_manager.qkd_driver.get_qkd_key(session_id)
                logger.info("QKD key retrieved successfully", session_id=session_id)
                return key, metadata, True
            except Exception as e:
                logger.warning("QKD key retrieval failed, attempting failover",
                             session_id=session_id, error=str(e))

                # Log failover event
                QKD_FAILOVER_EVENTS.labels(reason='key_retrieval_failure').inc()

        # Fallback to PQC-only
        logger.info("Using PQC-only fallback mode", session_id=session_id)
        key, metadata = self.pqc_fallback(session_id)
        return key, metadata, False

def default_alert_callback(old_status: QKDHealthStatus, new_status: QKDHealthStatus, metadata: Dict[str, Any]):
    """Default alert callback that logs status changes."""
    severity_map = {
        QKDHealthStatus.HEALTHY: "info",
        QKDHealthStatus.DEGRADED: "warning",
        QKDHealthStatus.FAILED: "error",
        QKDHealthStatus.UNKNOWN: "warning"
    }

    log_func = getattr(logger, severity_map.get(new_status, "info"))
    log_func("QKD status alert",
             old_status=old_status.value,
             new_status=new_status.value,
             metadata=metadata)

# Global failover manager instance
_failover_manager: Optional[QKDFailoverManager] = None

def init_failover_manager(qkd_driver: IQKDDriver) -> QKDFailoverManager:
    """Initialize the global QKD failover manager."""
    global _failover_manager
    if _failover_manager is None:
        _failover_manager = QKDFailoverManager(qkd_driver)
        _failover_manager.add_alert_callback(default_alert_callback)
        _failover_manager.start_monitoring()
    return _failover_manager

def get_failover_manager() -> Optional[QKDFailoverManager]:
    """Get the global failover manager instance."""
    return _failover_manager

def shutdown_failover():
    """Shutdown the failover manager."""
    global _failover_manager
    if _failover_manager:
        _failover_manager.stop_monitoring()
        _failover_manager = None
