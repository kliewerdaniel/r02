#!/usr/bin/env python3
"""
QASP v0.2 SDK Demo

Demonstrates basic usage of the QASP v0.2 Python client SDK.
Shows client registration, handshake initialization, and resource access.
"""

import logging
from qasp_sdk import QASPClient

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def main():
    """Main demonstration function."""
    # Initialize client
    server_url = "http://localhost:8000"
    tenant_id = "demo-tenant"
    client_id = "demo-client"

    logger.info("Initializing QASP client...")
    client = QASPClient(server_url, tenant_id)

    # Register client
    logger.info("Registering client...")
    if not client.register_client(client_id):
        logger.error("Failed to register client")
        return

    # Initialize handshake
    logger.info("Initializing handshake...")
    session_token = client.init_handshake(use_qkd=False)
    if not session_token:
        logger.error("Failed to initialize handshake")
        return

    logger.info(f"Session established with token: {session_token[:32]}...")

    # Perform challenge
    logger.info("Performing challenge verification...")
    if not client.challenge():
        logger.error("Challenge verification failed")
        return

    # Request protected resource
    logger.info("Requesting protected resource...")
    resource = client.request_resource()
    if resource:
        logger.info(f"Received resource: {resource['plaintext']}")
    else:
        logger.error("Failed to access protected resource")

    # Close session
    client.close_session()
    logger.info("Demo completed successfully")


if __name__ == "__main__":
    main()
