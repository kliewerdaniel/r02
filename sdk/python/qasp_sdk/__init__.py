"""
QASP v0.2 Python Client SDK

A minimal Python SDK for interacting with QASP v0.2 servers.
Provides functions for client registration, handshake initialization,
challenge verification, and resource access.
"""

from .client import QASPClient

__version__ = "0.2.0"
__all__ = ["QASPClient"]
