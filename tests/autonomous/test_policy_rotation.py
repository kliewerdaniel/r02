"""
Test autonomous policy rotation functionality.

Tests the end-to-end adaptive cryptography system including threat evaluation,
AI-driven recommendations, and automatic algorithm rotation with rollback.
"""

import json
import time
import unittest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import tempfile
import os

# Add src to path for imports
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from src.orchestration.adaptive_controller import AdaptiveController, TelemetrySnapshot
from src.ai_threat.policy_agent import PolicyAgent
from src.analytics.metrics_collector import LTSMetricsCollector


class TestPolicyRotation(unittest.TestCase):
    """Test cases for autonomous policy-driven algorithm rotation."""

    def setUp(self):
        """Set up test fixtures."""
        # Mock the policy agent
        self.mock_agent = Mock(spec=PolicyAgent)

        # Mock metrics collector
        self.mock_collector = Mock(spec=LTSMetricsCollector)
        self.mock_collector.get_threat_score.return_value = 0.3

        # Create controller with mocks
        self.controller = AdaptiveController(
            policy_agent=self.mock_agent,
            metrics_collector=self.mock_collector
        )

        # Reset environment variables for consistent testing
        os.environ["KEM_ALG"] = "Kyber512"
        os.environ["SIG_ALG"] = "Dilithium3"

    def tearDown(self):
        """Clean up after tests."""
        # Reset environment variables
        if "KEM_ALG" in os.environ:
            del os.environ["KEM_ALG"]
        if "SIG_ALG" in os.environ:
            del os.environ["SIG_ALG"]

    def test_low_threat_no_rotation(self):
        """Test that low threat levels do not trigger rotation."""
        # Create low-threat telemetry
        telemetry = TelemetrySnapshot(
            timestamp=time.time(),
            latency_ms=50.0,
            failures=1,
            qkd_health=0.95,
            threat_score=0.2
        )

        self.controller.update_telemetry(telemetry)
        evaluation = self.controller.evaluate_threat_surface()

        # Should be low threat
        self.assertEqual(evaluation["threat_level"], "low")
        self.assertIn("No threat triggers detected", evaluation["triggers"])

        # Get recommendation - should be "maintain"
        recommendation = self.controller.recommend_algorithm_change(evaluation)
        self.assertEqual(recommendation["action"], "maintain")
        self.assertIsNone(recommendation["new_algorithms"])

    def test_high_threat_triggers_rotation(self):
        """Test that high threat levels trigger algorithm rotation."""
        # Mock AI agent to recommend rotation
        mock_recommendation = {
            "action": "rotate",
            "new_algorithms": {"kem": "Kyber768", "sig": "Dilithium3"},
            "confidence": 0.85,
            "reason": "High threat level detected",
            "risk_assessment": "medium",
            "current_algorithms": {"kem": "Kyber512", "sig": "Dilithium3"}
        }
        self.mock_agent.get_policy_recommendation.return_value = mock_recommendation

        # Create high-threat telemetry
        telemetry = TelemetrySnapshot(
            timestamp=time.time(),
            latency_ms=150.0,  # High latency
            failures=50,  # High failure rate
            qkd_health=0.7,  # Degraded QKD
            threat_score=0.8  # High threat
        )

        self.controller.update_telemetry(telemetry)
        evaluation = self.controller.evaluate_threat_surface()

        # Should be high threat
        self.assertIn(evaluation["threat_level"], ["high", "critical"])
        self.assertGreater(len(evaluation["triggers"]), 1)

        # Get recommendation - should be "rotate"
        recommendation = self.controller.recommend_algorithm_change(evaluation)
        self.assertEqual(recommendation["action"], "rotate")
        self.assertIsNotNone(recommendation["new_algorithms"])

    def test_algorithm_validation(self):
        """Test that invalid algorithms are properly validated."""
        # Test with invalid KEM algorithm
        invalid_rec = {
            "action": "rotate",
            "new_algorithms": {"kem": "invalid_kem", "sig": "Dilithium3"},
            "confidence": 0.8,
            "reason": "Test invalid algorithm"
        }

        is_valid = self.controller._validate_recommendation(invalid_rec)
        self.assertFalse(is_valid)

        # Test with valid algorithms
        valid_rec = {
            "action": "rotate",
            "new_algorithms": {"kem": "Kyber768", "sig": "Dilithium5"},
            "confidence": 0.8,
            "reason": "Test valid algorithm"
        }

        is_valid = self.controller._validate_recommendation(valid_rec)
        self.assertTrue(is_valid)

    @patch.dict(os.environ, {"KEM_ALG": "Kyber512", "SIG_ALG": "Dilithium3"})
    def test_rotation_execution(self):
        """Test successful algorithm rotation execution."""
        # Change tracking
        original_kem = os.environ.get("KEM_ALG")
        original_sig = os.environ.get("SIG_ALG")

        recommendation = {
            "action": "rotate",
            "new_algorithms": {"kem": "Kyber768", "sig": "Dilithium5"},
            "confidence": 0.9,
            "reason": "Automated rotation test"
        }

        # Execute rotation
        success = self.controller.execute_rotation(recommendation)

        # Verify environment variables changed
        self.assertEqual(os.environ["KEM_ALG"], "Kyber768")
        self.assertEqual(os.environ["SIG_ALG"], "Dilithium5")

        # Verify controller state updated
        self.assertEqual(self.controller.current_kem, "Kyber768")
        self.assertEqual(self.controller.current_sig, "Dilithium5")

        # Verify decision was logged
        self.assertGreater(len(self.controller.decision_log), 0)
        last_decision = self.controller.decision_log[-1]
        self.assertEqual(last_decision.action, "rotate")
        self.assertEqual(last_decision.new_algorithms, {"kem": "Kyber768", "sig": "Dilithium5"})

        # Rotate back for cleanup
        rollback_rec = {
            "action": "rotate",
            "new_algorithms": {"kem": original_kem, "sig": original_sig},
            "confidence": 1.0,
            "reason": "Rollback to original"
        }
        self.controller.execute_rotation(rollback_rec)

    def test_rule_based_fallback(self):
        """Test rule-based algorithm recommendations when AI is unavailable."""
        # Make AI agent unavailable
        self.mock_agent.get_policy_recommendation.return_value = None

        # Create medium-high threat scenario
        telemetry = TelemetrySnapshot(
            timestamp=time.time(),
            latency_ms=120.0,
            failures=20,
            qkd_health=0.85,
            threat_score=0.6
        )

        self.controller.update_telemetry(telemetry)
        evaluation = self.controller.evaluate_threat_surface()

        # Should trigger medium or higher threat
        self.assertIn(evaluation["threat_level"], ["medium", "high", "critical"])

        # Get rule-based recommendation
        recommendation = self.controller.recommend_algorithm_change(evaluation)

        # Should use rule-based logic
        if evaluation["threat_level"] in ["high", "critical"]:
            # Should recommend upgrading algorithms
            expected_kem = "Kyber768" if self.controller.current_kem == "Kyber512" else "Kyber512"
            self.assertIn(recommendation["action"], ["rotate", "maintain"])
            if recommendation["action"] == "rotate":
                self.assertIsNotNone(recommendation["new_algorithms"])

    def test_decision_persistence(self):
        """Test that policy decisions are persisted to disk."""
        recommendation = {
            "action": "rotate",
            "new_algorithms": {"kem": "Kyber768", "sig": "Dilithium3"},
            "confidence": 0.8,
            "reason": "Persistence test"
        }

        # Execute rotation to trigger logging
        self.controller.execute_rotation(recommendation)

        # Check if policy decisions file was created
        policy_file = Path("reports/policy_decisions.json")
        self.assertTrue(policy_file.exists())

        # Verify content
        with open(policy_file, 'r') as f:
            decisions_data = json.load(f)

        self.assertIn("decisions", decisions_data)
        self.assertGreater(len(decisions_data["decisions"]), 0)

        last_decision = decisions_data["decisions"][-1]
        self.assertEqual(last_decision["action"], "rotate")
        self.assertEqual(last_decision["new_algorithms"], {"kem": "Kyber768", "sig": "Dilithium3"})

    def test_policy_state_api(self):
        """Test the policy state API endpoint data."""
        # Add some telemetry and decisions
        telemetry = TelemetrySnapshot(
            timestamp=time.time(),
            latency_ms=60.0,
            failures=5,
            qkd_health=0.9,
            threat_score=0.3
        )
        self.controller.update_telemetry(telemetry)

        # Execute a rotation
        rec = {
            "action": "rotate",
            "new_algorithms": {"kem": "Kyber768", "sig": "Dilithium3"},
            "confidence": 0.75,
            "reason": "API test"
        }
        self.controller.execute_rotation(rec)

        # Get policy state
        state = self.controller.get_current_policy_state()

        # Verify structure
        self.assertIn("timestamp", state)
        self.assertIn("current_algorithms", state)
        self.assertIn("threat_evaluation", state)
        self.assertIn("last_decision", state)

        # Verify algorithms
        self.assertEqual(state["current_algorithms"]["kem"], "Kyber768")
        self.assertEqual(state["current_algorithms"]["signature"], "Dilithium3")

        # Verify threat evaluation
        self.assertIn("threat_level", state["threat_evaluation"])
        self.assertGreater(len(state["threat_evaluation"]), 0)

    def test_telemetry_buffering(self):
        """Test that telemetry is properly buffered and managed."""
        initial_count = len(self.controller.telemetry_history)

        # Add telemetry up to the limit
        for i in range(self.controller.max_telemetry_history + 5):
            telemetry = TelemetrySnapshot(
                timestamp=time.time() + i,
                latency_ms=50.0 + i,
                failures=i % 10,
                qkd_health=0.9,
                threat_score=0.2
            )
            self.controller.update_telemetry(telemetry)

        # Verify buffer size is maintained
        self.assertEqual(len(self.controller.telemetry_history), self.controller.max_telemetry_history)

        # Verify oldest entries were removed (should have higher latency values now)
        latencies = [t.latency_ms for t in self.controller.telemetry_history]
        min_latency = min(latencies)
        self.assertGreater(min_latency, 50.0)  # Should be > initial values


if __name__ == '__main__':
    unittest.main()
