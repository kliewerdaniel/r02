"""
QASP v0.2 Formal Verification Tests - Trace Logging

Tests for the formal verification trace logging system.
Verifies that protocol events are properly logged for offline analysis.
"""

import os
import json
import pytest
from src.formal.qasp_model import (
    write_trace_log,
    get_trace_log,
    clear_trace_log,
    STATES,
    trace_handshake_init,
    validate_state_transition
)


class TestTraceLogging:
    """Test trace log functionality."""

    def setup_method(self):
        """Clear trace log before each test."""
        clear_trace_log()

    def teardown_method(self):
        """Clean up after each test."""
        clear_trace_log()

    def test_write_trace_log_basic(self):
        """Test basic trace log writing."""
        payload = {
            "session_id": "test-session-123",
            "client_id": "test-client",
            "tenant_id": "test-tenant"
        }

        write_trace_log("handshake_init", payload)

        # Read back
        logs = get_trace_log()
        assert len(logs) == 1

        entry = logs[0]
        assert entry["event_type"] == "handshake_init"
        assert entry["qasp_version"] == "0.2"
        assert entry["payload"] == payload
        assert "timestamp" in entry

    def test_trace_convenience_functions(self):
        """Test convenience functions for common events."""
        session_id = "session-456"
        tenant_id = "tenant-ABC"
        client_id = "client-XYZ"

        trace_handshake_init(session_id, tenant_id, client_id)

        logs = get_trace_log()
        assert len(logs) == 1
        assert logs[0]["event_type"] == "handshake_init"
        assert logs[0]["payload"]["session_id"] == session_id
        assert logs[0]["payload"]["tenant_id"] == tenant_id
        assert logs[0]["payload"]["client_id"] == client_id
        assert logs[0]["payload"]["state"] == STATES["INIT"]

    def test_multiple_entries(self):
        """Test multiple trace entries."""
        # Write several entries
        write_trace_log("event1", {"key": "value1"})
        write_trace_log("event2", {"key": "value2"})
        write_trace_log("event3", {"key": "value3"})

        logs = get_trace_log()
        assert len(logs) == 3
        assert [log["event_type"] for log in logs] == ["event1", "event2", "event3"]

    def test_trace_log_persistence(self):
        """Test that trace log persists between writes."""
        write_trace_log("first", {"data": 1})

        # Get logs - should have 1 entry
        logs = get_trace_log()
        assert len(logs) == 1

        # Add another entry
        write_trace_log("second", {"data": 2})

        # Should now have 2 entries
        logs = get_trace_log()
        assert len(logs) == 2
        assert logs[0]["event_type"] == "first"
        assert logs[1]["event_type"] == "second"

    def test_clear_trace_log(self):
        """Test clearing the trace log."""
        # Add some entries
        write_trace_log("test", {"value": "data"})

        # Verify they exist
        logs = get_trace_log()
        assert len(logs) == 1

        # Clear
        clear_trace_log()

        # Verify cleared
        logs = get_trace_log()
        assert len(logs) == 0

    def test_error_handling(self):
        """Test error handling in trace logging."""
        # This should not raise an exception even if something fails
        # (logging errors are logged but don't break protocol flow)

        # Pass invalid payload that might cause JSON issues
        write_trace_log("test_event", {"invalid": object()})  # object() not JSON serializable

        # The trace log write should handle this gracefully
        # (though it may log an error internally)
        logs = get_trace_log()
        # Might have 0 or 1 entries depending on error handling implementation
        assert len(logs) <= 1  # Should not crash


class TestStateTransitions:
    """Test handshake state transition validation."""

    def test_valid_transitions(self):
        """Test valid state transitions."""
        assert validate_state_transition("INIT", "CHALLENGE", "handshake_start") == True
        assert validate_state_transition("CHALLENGE", "ESTABLISHED", "challenge_success") == True
        assert validate_state_transition("ESTABLISHED", "INIT", "session_expire") == True
        assert validate_state_transition("CHALLENGE", "INIT", "challenge_failure") == True

    def test_invalid_transitions(self):
        """Test invalid state transitions."""
        assert validate_state_transition("INIT", "ESTABLISHED", "skip_challenge") == False
        assert validate_state_transition("ESTABLISHED", "CHALLENGE", "invalid_backtrack") == False
        assert validate_state_transition("UNKNOWN", "INIT", "bad_state") == False

    def test_unknown_states(self):
        """Test handling of unknown states."""
        assert validate_state_transition("NONEXISTENT", "INIT", "test") == False
        assert validate_state_transition("INIT", "NONEXISTENT", "test") == False


class TestProtocolConstants:
    """Test protocol constants and configuration."""

    def test_states_defined(self):
        """Test that handshake states are properly defined."""
        assert STATES["INIT"] == "handshake_initialization"
        assert STATES["CHALLENGE"] == "challenge_verification"
        assert STATES["ESTABLISHED"] == "session_established"

        assert len(STATES) == 3

    def test_protocol_constraints(self):
        """Test protocol constraint constants."""
        from src.formal.qasp_model import PROTOCOL_VERSION, MAX_MESSAGE_SIZE

        assert PROTOCOL_VERSION == "0.2"
        assert MAX_MESSAGE_SIZE == 65536  # 64KB

    def test_supported_algorithms(self):
        """Test supported algorithm lists."""
        from src.formal.qasp_model import (
            SUPPORTED_KEM_ALGORITHMS,
            SUPPORTED_SIGNATURE_ALGORITHMS,
            SUPPORTED_SYMMETRIC_ALGORITHMS
        )

        # Check KEM algorithms
        assert "Kyber512" in SUPPORTED_KEM_ALGORITHMS
        assert "Kyber768" in SUPPORTED_KEM_ALGORITHMS
        assert "Kyber1024" in SUPPORTED_KEM_ALGORITHMS

        # Check signature algorithms
        assert "Dilithium2" in SUPPORTED_SIGNATURE_ALGORITHMS
        assert "Dilithium3" in SUPPORTED_SIGNATURE_ALGORITHMS
        assert "Dilithium5" in SUPPORTED_SIGNATURE_ALGORITHMS

        # Check symmetric algorithms
        assert "AES-GCM" in SUPPORTED_SYMMETRIC_ALGORITHMS
        assert "ChaCha20-Poly1305" in SUPPORTED_SYMMETRIC_ALGORITHMS


class TestTransitionModel:
    """Test the handshake transition model."""

    def test_transition_definitions(self):
        """Test that transition model is properly defined."""
        from src.formal.qasp_model import HANDSHAKE_TRANSITIONS

        assert "INIT" in HANDSHAKE_TRANSITIONS
        assert "CHALLENGE" in HANDSHAKE_TRANSITIONS
        assert "ESTABLISHED" in HANDSHAKE_TRANSITIONS

        assert HANDSHAKE_TRANSITIONS["INIT"] == ["CHALLENGE"]
        assert HANDSHAKE_TRANSITIONS["CHALLENGE"] == ["ESTABLISHED", "INIT"]
        assert HANDSHAKE_TRANSITIONS["ESTABLISHED"] == ["INIT"]
