"""
QASP v0.2 Conformance Tests - Message Serialization

Tests for canonical JSON serialization/deserialization and message schema validation.
Uses golden file testing to ensure cross-implementation stability.
"""

import json
import os
import pytest
from src.interop.qasp_interop import (
    serialize_handshake,
    deserialize_handshake,
    validate_message_schema
)


# Reference messages for testing (golden files)
REFERENCE_MESSAGES = {
    "handshake_init": {
        "qasp_version": "0.2",
        "type": "handshake_init",
        "client_id": "test-client-123",
        "tenant_id": "test-tenant",
        "kem_encaps": "SGVsbG8gV29ybGQ=",  # base64 "Hello World"
        "client_nonce": "VGVzdCBOb25jZQ==",  # base64 "Test Nonce"
        "supported_qkd": True
    },
    "challenge_request": {
        "qasp_version": "0.2",
        "type": "challenge_request",
        "challenge_nonce": "Q2hhbGxlbmdlIE5vbmNl",
        "challenge_ciphertext": "RW5jcnlwdGVkIENoYWxsZW5nZQ=="
    },
    "handshake_response": {
        "qasp_version": "0.2",
        "type": "handshake_response",
        "server_nonce": "U2VydmVyIE5vbmNl",
        "session_token": "QmFzZTY0IFNlc3Npb24gVG9rZW4="
    },
    "challenge_response": {
        "qasp_version": "0.2",
        "type": "challenge_response",
        "challenge_verified": True
    },
    "resource_response": {
        "qasp_version": "0.2",
        "type": "resource_response",
        "nonce": "RW5jcnlwdGlvbiBOb25jZQ==",
        "ciphertext": "RW5jcnlwdGVkIFJlc291cmNlIERhdGE="
    }
}

# Golden canonical JSON outputs
GOLDEN_SERIALIZED = {
    "handshake_init": '{"challenge_ciphertext":null,"challenge_nonce":null,"challenge_verified":null,"ciphertext":null,"client_id":"test-client-123","client_nonce":"VGVzdCBOb25jZQ==","kem_encaps":"SGVsbG8gV29ybGQ=","nonce":null,"qasp_version":"0.2","server_nonce":null,"session_token":null,"supported_qkd":true,"tenant_id":"test-tenant","type":"handshake_init"}',
    "challenge_request": '{"challenge_ciphertext":"RW5jcnlwdGVkIENoYWxsZW5nZQ==","challenge_nonce":"Q2hhbGxlbmdlIE5vbmNl","challenge_verified":null,"ciphertext":null,"client_id":null,"client_nonce":null,"kem_encaps":null,"nonce":null,"qasp_version":"0.2","server_nonce":null,"session_token":null,"supported_qkd":null,"tenant_id":null,"type":"challenge_request"}'
}


class TestMessageSerialization:
    """Test canonical JSON serialization."""

    @pytest.mark.parametrize("msg_type", REFERENCE_MESSAGES.keys())
    def test_serialization_canonical(self, msg_type):
        """Test that serialization produces canonical JSON."""
        message = REFERENCE_MESSAGES[msg_type]

        # Serialize
        serialized = serialize_handshake(message)

        # Verify it's valid JSON
        parsed = json.loads(serialized)
        assert parsed == message

        # Verify canonical ordering (sorted keys)
        expected_keys = sorted(message.keys())
        parsed_keys = list(parsed.keys())
        assert parsed_keys == expected_keys

        # Verify no whitespace
        assert " " not in serialized
        assert "\n" not in serialized
        assert "\t" not in serialized

    def test_serialization_golden_files(self):
        """Test against golden reference files (where they exist)."""
        for msg_type in ["handshake_init", "challenge_request"]:
            if msg_type in GOLDEN_SERIALIZED:
                message = REFERENCE_MESSAGES[msg_type]
                serialized = serialize_handshake(message)
                assert serialized == GOLDEN_SERIALIZED[msg_type]

    @pytest.mark.parametrize("msg_type", REFERENCE_MESSAGES.keys())
    def test_roundtrip_serialization(self, msg_type):
        """Test serialize -> deserialize -> serialize produces same result."""
        original = REFERENCE_MESSAGES[msg_type]

        # Round trip
        serialized = serialize_handshake(original)
        deserialized = deserialize_handshake(serialized)
        reserialized = serialize_handshake(deserialized)

        assert serialized == reserialized

    def test_version_enforcement(self):
        """Test that version is properly enforced."""
        message = REFERENCE_MESSAGES["handshake_init"].copy()
        message["qasp_version"] = "0.1"

        # Should raise ValueError
        with pytest.raises(ValueError):
            serialize_handshake(message)

    def test_version_added_automatically(self):
        """Test that qasp_version is added if missing."""
        message = REFERENCE_MESSAGES["handshake_init"].copy()
        del message["qasp_version"]

        serialized = serialize_handshake(message)

        # Should have version field now
        deserialized = deserialize_handshake(serialized)
        assert deserialized["qasp_version"] == "0.2"


class TestMessageValidation:
    """Test message schema validation."""

    @pytest.mark.parametrize("msg_type", REFERENCE_MESSAGES.keys())
    def test_valid_messages(self, msg_type):
        """Test that reference messages validate successfully."""
        message = REFERENCE_MESSAGES[msg_type]
        assert validate_message_schema(message) == True

    def test_invalid_version(self):
        """Test rejection of invalid versions."""
        message = REFERENCE_MESSAGES["handshake_init"].copy()
        message["qasp_version"] = "0.3"
        assert validate_message_schema(message) == False

    def test_missing_required_fields(self):
        """Test rejection of messages with missing required fields."""
        # Missing type field
        message = REFERENCE_MESSAGES["handshake_init"].copy()
        del message["type"]
        assert validate_message_schema(message) == False

        # Missing client_id for handshake_init
        message = REFERENCE_MESSAGES["handshake_init"].copy()
        del message["client_id"]
        assert validate_message_schema(message) == False

    def test_invalid_base64(self):
        """Test rejection of messages with invalid base64."""
        message = REFERENCE_MESSAGES["handshake_init"].copy()
        message["kem_encaps"] = "invalid-base64!"
        assert validate_message_schema(message) == False

    def test_unknown_message_type(self):
        """Test that unknown message types are rejected."""
        message = REFERENCE_MESSAGES["handshake_init"].copy()
        message["type"] = "unknown_type"
        assert validate_message_schema(message) == False


class TestCrossLanguageCompatibility:
    """Test compatibility with other implementations."""

    def test_deterministic_output(self):
        """Test that identical inputs produce identical outputs."""
        message = REFERENCE_MESSAGES["handshake_init"]

        # Serialize multiple times - should be identical
        serialized1 = serialize_handshake(message)
        serialized2 = serialize_handshake(message)

        assert serialized1 == serialized2

    def test_key_order_irrelevant(self):
        """Test that input key order doesn't affect output."""
        message = REFERENCE_MESSAGES["handshake_init"]

        # Shuffle key order
        import random
        keys = list(message.keys())
        random.shuffle(keys)
        shuffled_message = {k: message[k] for k in keys}

        # Should produce same serialization
        original_serialized = serialize_handshake(message)
        shuffled_serialized = serialize_handshake(shuffled_message)

        assert original_serialized == shuffled_serialized
