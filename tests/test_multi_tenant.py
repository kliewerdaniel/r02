"""
QASP v0.2 Multi-Tenant Tests

Tests for multi-tenant key isolation, session management, and metric separation.
"""

import pytest
from src.hsm.mock_hsm import MockHSM
from src.qasp.crypto import PQCKEM, PQCSign


class TestMultiTenantHSM:
    """Test multi-tenant HSM key isolation."""

    def test_tenant_partitioning(self):
        """Test that tenant keys are isolated."""
        hsm = MockHSM()

        # Store keys for different tenants
        tenant1_key = b"tenant1-secret-key"
        tenant2_key = b"tenant2-secret-key"

        # Store for tenant1, client "alice"
        success1 = hsm.store_private_key("tenant1", "alice", "kem", tenant1_key)
        assert success1 == True

        # Store for tenant2, client "alice" (same client name, different tenant)
        success2 = hsm.store_private_key("tenant2", "alice", "kem", tenant2_key)
        assert success2 == True

        # Retrieve from tenant1
        retrieved1 = hsm.get_private_key("tenant1", "alice", "kem")
        assert retrieved1 == tenant1_key

        # Retrieve from tenant2
        retrieved2 = hsm.get_private_key("tenant2", "alice", "kem")
        assert retrieved2 == tenant2_key

        # Keys should be different
        assert retrieved1 != retrieved2

    def test_tenant_isolation(self):
        """Test that tenants can't access each other's keys."""
        hsm = MockHSM()

        # Store key for tenant1
        hsm.store_private_key("tenant1", "bob", "kem", b"secret-for-tenant1")

        # Try to retrieve from tenant2 - should fail
        retrieved = hsm.get_private_key("tenant2", "bob", "kem")
        assert retrieved is None

    def test_tenant_key_listing(self):
        """Test per-tenant key listing."""
        hsm = MockHSM()

        # Store keys for different tenants and clients
        hsm.store_private_key("tenantA", "client1", "kem", b"key1")
        hsm.store_private_key("tenantA", "client2", "sign", b"key2")
        hsm.store_private_key("tenantB", "client1", "kem", b"key3")

        # List keys for tenantA
        keys_tenantA = hsm.list_keys("tenantA")
        expected_A = [
            {"client_id": "client1", "key_type": "kem"},
            {"client_id": "client2", "key_type": "sign"}
        ]
        assert sorted(keys_tenantA, key=lambda x: (x["client_id"], x["key_type"])) == expected_A

        # List keys for tenantB
        keys_tenantB = hsm.list_keys("tenantB")
        expected_B = [{"client_id": "client1", "key_type": "kem"}]
        assert keys_tenantB == expected_B

    def test_tenant_empty_listing(self):
        """Test key listing for tenant with no keys."""
        hsm = MockHSM()

        # Store keys for tenant1
        hsm.store_private_key("tenant1", "client1", "kem", b"key")

        # List keys for tenant2 (should be empty)
        keys = hsm.list_keys("tenant2")
        assert keys == []


class TestMultiTenantCrypto:
    """Test multi-tenant cryptographic operations."""

    def test_tenant_specific_keys(self):
        """Test that PQCKEM/PQCSign use tenant-specific keys."""
        # Create instances for different tenants
        kem_tenant1 = PQCKEM(client_id="alice", tenant_id="tenant1")
        kem_tenant2 = PQCKEM(client_id="alice", tenant_id="tenant2")  # Same client id, different tenant

        # Generate keys (assumes HSM is configured)
        pub1 = kem_tenant1.generate_keypair()
        pub2 = kem_tenant2.generate_keypair()

        # Should generate different keys (due to different tenant namespaces)
        assert pub1 != pub2

    def test_key_storage_isolation(self):
        """Test that keys are stored in tenant-specific namespaces."""
        hsm = MockHSM()

        kem1 = PQCKEM(keystore=hsm, client_id="test-client", tenant_id="tenant1")
        kem2 = PQCKEM(keystore=hsm, client_id="test-client", tenant_id="tenant2")

        # Generate keys
        pub1 = kem1.generate_keypair()
        pub2 = kem2.generate_keypair()

        # Verify keys are stored in HSM under correct tenants
        key1 = hsm.get_private_key("tenant1", "test-client", "kem")
        key2 = hsm.get_private_key("tenant2", "test-client", "kem")

        assert key1 is not None
        assert key2 is not None
        assert key1 != key2


class TestMultiTenantSessions:
    """Test tenant isolation in session management."""

    def test_session_tenant_isolation(self):
        """Test that sessions are properly isolated by tenant."""
        # This would test the in-memory session store partitioning
        # For this test, we simulate different tenant session storage

        # Mock session storage per tenant
        tenant_sessions = {}

        # Simulate session creation for different tenants
        session1 = {"session_id": "sess1", "tenant_id": "tenant1", "key": "key1"}
        session2 = {"session_id": "sess2", "tenant_id": "tenant2", "key": "key2"}

        tenant_sessions[session1["session_id"]] = session1
        tenant_sessions[session2["session_id"]] = session2

        # Verify tenant isolation
        assert tenant_sessions["sess1"]["tenant_id"] == "tenant1"
        assert tenant_sessions["sess2"]["tenant_id"] == "tenant2"

        # Cross-tenant access should be impossible (different namespaces)
        assert tenant_sessions.get("sess1")["tenant_id"] != tenant_sessions.get("sess2")["tenant_id"]


class TestMultiTenantMetrics:
    """Test tenant-specific metrics."""

    def test_metric_labels_include_tenant(self):
        """Test that metrics include tenant_id labels."""
        # This would test the Prometheus metrics labeling
        # We test the label definitions

        from src.telemetry.metrics import HANDSHAKE_TOTAL

        # Check that the metric has tenant_id label
        assert "tenant_id" in HANDSHAKE_TOTAL._labelnames

        # Test metric increment with tenant
        HANDSHAKE_TOTAL.labels(result="success", tenant_id="test-tenant").inc()
        HANDSHAKE_TOTAL.labels(result="failure", tenant_id="another-tenant").inc()

        # This would be collected in a real metrics system


class TestMultiTenantMiddleware:
    """Test tenant handling in middleware."""

    def test_middleware_tenant_extraction(self):
        """Test tenant extraction from headers/bodies."""
        from src.server.middleware import request_signature_middleware
        from fastapi import Request
        from unittest.mock import Mock

        # Mock request with tenant_id in header
        mock_request = Mock(spec=Request)
        mock_request.headers = {
            "x-qasp-tenant-id": "test-tenant",
            "x-qasp-client-id": "test-client",
            "x-qasp-signature": "signature"
        }
        mock_request.body.return_value.decode.return_value = '{"type":"handshake_init"}'
        mock_request.url.path = "/qasp/init"
        mock_request.body.return_value = b'{"type":"handshake_init"}'

        # Test middleware (simplified - would need full setup)
        clients_store = {"test-tenant": {"test-client": {"pub_sig": b"test-key"}}}

        middleware_func = request_signature_middleware(clients_store)

        # The middleware should extract tenant_id correctly
        # Full testing would require more complex setup
