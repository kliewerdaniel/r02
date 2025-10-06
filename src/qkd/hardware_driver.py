from abc import ABC, abstractmethod
import os
import time
import hashlib
import uuid
import base64
from typing import Tuple, Dict, Any


class IQKDDriver(ABC):
    """
    Abstract base class for QKD hardware drivers.
    """

    @abstractmethod
    def get_qkd_key(self, session_id: str) -> Tuple[bytes, Dict[str, Any]]:
        """
        Retrieve a QKD key for the given session.

        Args:
            session_id: Unique session identifier.

        Returns:
            Tuple of (key_bytes, metadata_dict).
            Metadata includes keys like 'latency_ms', 'device_id', etc.
        """
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """
        Check if the QKD hardware/driver is available.
        """
        pass


class SimulatedQKDDriver(IQKDDriver):
    """
    Simulated QKD driver that returns keys from a mock device API.
    Generates deterministic keys for testing purposes.
    """

    def __init__(self):
        self.device_id = "sim-qkd-001"
        self._key_counter = 0

    def get_qkd_key(self, session_id: str) -> Tuple[bytes, Dict[str, Any]]:
        start_time = time.time()
        self._key_counter += 1
        # Simulate some latency
        import time
        time.sleep(0.01)  # 10ms simulated latency

        # Generate deterministic key based on session_id and counter
        key_input = f"{session_id}-{self._key_counter}".encode()
        key = hashlib.sha256(key_input).digest()[:32]  # 256-bit key

        latency_ms = (time.time() - start_time) * 1000
        metadata = {
            "latency_ms": round(latency_ms, 2),
            "device_id": self.device_id,
            "device_type": "simulated",
            "key_length_bits": len(key) * 8
        }
        return key, metadata

    def is_available(self) -> bool:
        return True


class HardwareQKDDriver(IQKDDriver):
    """
    Hardware QKD driver wrapper for vendor SDK (e.g., ID Quantique Cerberis or Toshiba QKD Link).
    Placeholder implementation assuming SDK integration.
    """

    def __init__(self, vendor_sdk_config: Dict[str, Any] = None):
        # In real implementation, initialize vendor SDK here
        # For example:
        # from vendor_sdk import QKDLink
        # self.link = QKDLink(config=vendor_sdk_config)
        self.vendor_sdk_config = vendor_sdk_config or {}
        self.device_id = vendor_sdk_config.get("device_id", "hw-qkd-001")
        self.device_type = vendor_sdk_config.get("device_type", "unknown")
        # Simulate SDK availability
        self._sdk_available = True  # In real: check if SDK can connect

    def get_qkd_key(self, session_id: str) -> Tuple[bytes, Dict[str, Any]]:
        if not self.is_available():
            raise RuntimeError("QKD hardware not available")

        start_time = time.time()
        # In real implementation, call vendor SDK API
        # key = self.link.generate_key_for_session(session_id)
        # Simulate key generation
        import random
        key = os.urandom(32)  # Simulate random key from hardware

        latency_ms = (time.time() - start_time) * 1000
        metadata = {
            "latency_ms": round(latency_ms, 2),
            "device_id": self.device_id,
            "device_type": self.device_type,
            "key_length_bits": 256,
            "vendor": self.vendor_sdk_config.get("vendor", "unknown")
        }
        return key, metadata

    def is_available(self) -> bool:
        # In real: check hardware connection, SDK status, etc.
        return self._sdk_available


class HuaweiQKDDriver(IQKDDriver):
    """
    Mock Huawei QKD driver for simulation.
    """
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.device_id = self.config.get("device_id", "huawei-qkd-001")

    def get_qkd_key(self, session_id: str) -> Tuple[bytes, Dict[str, Any]]:
        start_time = time.time()
        time.sleep(0.015)  # Simulated latency
        key = hashlib.sha3_256(f"{session_id}-{uuid.uuid4()}".encode()).digest()[:32]
        latency_ms = (time.time() - start_time) * 1000
        metadata = {
            "latency_ms": round(latency_ms, 2),
            "device_id": self.device_id,
            "vendor": "Huawei",
            "key_length_bits": 256
        }
        return key, metadata

    def is_available(self) -> bool:
        return True


class QuantumXchangePhioDriver(IQKDDriver):
    """
    Mock Quantum Xchange Phio QKD driver for simulation.
    """
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.device_id = self.config.get("device_id", "qx-phio-qkd-001")

    def get_qkd_key(self, session_id: str) -> Tuple[bytes, Dict[str, Any]]:
        start_time = time.time()
        time.sleep(0.012)  # Simulated latency
        key = hashlib.sha3_512(f"{session_id}-{uuid.uuid4()}".encode()).digest()[:32]
        latency_ms = (time.time() - start_time) * 1000
        metadata = {
            "latency_ms": round(latency_ms, 2),
            "device_id": self.device_id,
            "vendor": "QuantumXchange",
            "key_length_bits": 256
        }
        return key, metadata

    def is_available(self) -> bool:
        return True


# Multi-vendor plugin registry
QKD_DRIVERS_REGISTRY = {
    "simulated": SimulatedQKDDriver,
    "huawei": HuaweiQKDDriver,
    "quantumxchange_phio": QuantumXchangePhioDriver,
}


def load_qkd_driver() -> IQKDDriver:
    """
    Load QKD driver based on environment configuration.
    Supports multi-vendor drivers via registry.
    """
    qkd_enabled = os.getenv("QKD_HARDWARE_ENABLED", "false").lower() == "true"
    qkd_vendor = os.getenv("QKD_VENDOR", "simulated")

    if not qkd_enabled:
        return SimulatedQKDDriver()  # Fallback to sim even if not enabled?

    if qkd_vendor in QKD_DRIVERS_REGISTRY:
        driver_class = QKD_DRIVERS_REGISTRY[qkd_vendor]
        if qkd_vendor == "simulated":
            return driver_class()
        else:
            # Load hardware config
            config = {
                "vendor": qkd_vendor,
                "device_id": os.getenv("QKD_DEVICE_ID", f"{qkd_vendor}-001"),
                "device_type": os.getenv("QKD_DEVICE_TYPE", "unknown")
            }
            return driver_class(config=config)
    else:
        raise ValueError(f"Unsupported QKD vendor: {qkd_vendor}. Available: {list(QKD_DRIVERS_REGISTRY.keys())}")
