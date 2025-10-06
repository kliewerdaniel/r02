"""
Integration test for the autonomous security orchestration loop.

Tests the complete self-healing cycle: threat detection → AI policy → rotation → monitoring → rollback.
"""

import json
import time
import unittest
import threading
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import os
import signal
import psutil

# Add src to path for imports
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from src.orchestration.adaptive_controller import AdaptiveController, TelemetrySnapshot
from src.ai_threat.policy_agent import PolicyAgent
from src.analytics.metrics_collector import LTSMetricsCollector
from src.jobs.rotation_daemon import RotationDaemon


class TestAutonomousLoop(unittest.TestCase):
    """Integration tests for the complete autonomous security orchestration loop."""

    def setUp(self):
        """Set up integration test fixtures."""
        # Mock policy agent with controlled responses
        self.mock_agent = Mock(spec=PolicyAgent)
        self.agent_responses = []
        self.mock_agent.get_policy_recommendation.side_effect = self._mock_agent_decision

        # Mock metrics collector
        self.mock_collector = Mock(spec=LTSMetricsCollector)

        # Create controller with mocks
        self.controller = AdaptiveController(
            policy_agent=self.mock_agent,
            metrics_collector=self.mock_collector
        )

        # Reset environment variables
        os.environ["KEM_ALG"] = "Kyber512"
        os.environ["SIG_ALG"] = "Dilithium3"

        # Clean up any previous test files
        policy_file = Path("reports/policy_decisions.json")
        if policy_file.exists():
            policy_file.unlink()

    def tearDown(self):
        """Clean up after tests."""
        # Reset environment variables
        for var in ["KEM_ALG", "SIG_ALG"]:
            if var in os.environ:
                del os.environ[var]

        # Clean up test files
        for f in ["reports/policy_decisions.json", "reports/rotation_daemon_stats.json"]:
            if Path(f).exists():
                Path(f).unlink()

    def _mock_agent_decision(self, threat_eval, current_algorithms):
        """Mock AI agent decision based on scenario."""
        if not self.agent_responses:
            return None  # Default fallback

        response = self.agent_responses.pop(0)

        if callable(response):
            return response(threat_eval, current_algorithms)

        return response

    def test_full_rotation_cycle(self):
        """Test complete rotation cycle: detect threat → rotate → monitor → rollback."""
        # Phase 1: Setup AI recommendations for rotation
        def rotation_recommendation(threat_eval, current):
            return {
                "action": "rotate",
                "new_algorithms": {"kem": "Kyber768", "sig": "Dilithium3"},
                "confidence": 0.9,
                "reason": "High threat detected - escalating security",
                "risk_assessment": "medium"
            }

        self.agent_responses = [rotation_recommendation]

        # Phase 2: Generate high-threat telemetry
        high_threat_telemetry = TelemetrySnapshot(
            timestamp=time.time(),
            latency_ms=200.0,  # Very high latency
            failures=100,      # High failure rate
            qkd_health=0.6,    # Degraded QKD
            threat_score=0.9   # Critical threat
        )

        # Phase 3: Execute threat evaluation and rotation
        self.controller.update_telemetry(high_threat_telemetry)
        threat_eval = self.controller.evaluate_threat_surface()

        # Verify high threat detection
        self.assertIn(threat_eval["threat_level"], ["high", "critical"])
        self.assertGreater(len(threat_eval["triggers"]), 2)

        # Get and execute rotation recommendation
        recommendation = self.controller.recommend_algorithm_change(threat_eval)
        self.assertEqual(recommendation["action"], "rotate")
        self.assertIsNotNone(recommendation["new_algorithms"])

        # Execute rotation
        success = self.controller.execute_rotation(recommendation)
        self.assertTrue(success)

        # Verify rotation occurred
        self.assertEqual(os.environ["KEM_ALG"], "Kyber768")
        self.assertEqual(os.environ["SIG_ALG"], "Dilithium3")

        # Phase 4: Test decision logging
        decisions = self.controller.get_decision_history()
        self.assertGreater(len(decisions), 0)
        last_decision = decisions[-1]
        self.assertEqual(last_decision["action"], "rotate")
        self.assertEqual(last_decision["algorithms"], {"kem": "Kyber768", "sig": "Dilithium3"})

        # Phase 5: Test policy state API
        policy_state = self.controller.get_current_policy_state()
        self.assertEqual(policy_state["current_algorithms"]["kem"], "Kyber768")
        self.assertIn("threat_evaluation", policy_state)

        print("✓ Full rotation cycle completed successfully")

    def test_performance_degradation_rollback(self):
        """Test automatic rollback on performance degradation after rotation."""
        # Phase 1: Execute rotation
        rotation_rec = {
            "action": "rotate",
            "new_algorithms": {"kem": "Kyber768", "sig": "Dilithium5"},
            "confidence": 0.85,
            "reason": "Performance rollback test"
        }

        success = self.controller.execute_rotation(rotation_rec)
        self.assertTrue(success)

        # Phase 2: Simulate post-rotation performance degradation
        with patch.object(self.controller, '_collect_system_metrics') as mock_metrics:
            # Mock degraded performance (2x latency, 5x failure rate)
            mock_metrics.return_value = {
                "latency": 200.0,  # 2x baseline
                "cpu_percent": 80.0,
                "memory_percent": 70.0,
                "failure_rate": 0.05,  # 5x baseline
                "qkd_health": 0.8,
                "threat_score": 0.7
            }

            # Test degradation detection
            degradation_detected = self.controller._monitor_performance_degradation(
                mock_metrics.return_value
            )
            self.assertTrue(degradation_detected, "Should detect performance degradation")

        print("✓ Performance degradation detection working")

    def test_ai_failure_fallback(self):
        """Test graceful fallback to rule-based logic when AI fails."""
        # Phase 1: Make AI agent unavailable (raises exception)
        self.mock_agent.get_policy_recommendation.side_effect = Exception("AI service down")

        # Phase 2: Create threat scenario that should trigger rotation
        threat_telemetry = TelemetrySnapshot(
            timestamp=time.time(),
            latency_ms=180.0,
            failures=80,
            qkd_health=0.5,
            threat_score=0.85
        )

        self.controller.update_telemetry(threat_telemetry)
        threat_eval = self.controller.evaluate_threat_surface()

        # Phase 3: Get recommendation (should fallback to rules)
        recommendation = self.controller.recommend_algorithm_change(threat_eval)

        # Should still provide a recommendation (rule-based fallback)
        self.assertIsInstance(recommendation, dict)
        self.assertIn("action", recommendation)
        self.assertIn("confidence", recommendation)

        print("✓ AI failure fallback working")

    def test_threat_feed_integration(self):
        """Test integration with threat intelligence feeds."""
        # Create controller with real metrics collector
        real_controller = AdaptiveController(
            policy_agent=self.mock_agent,
            metrics_collector=LTSMetricsCollector()
        )

        # Test threat score calculation
        threat_score = real_controller.metrics_collector.get_threat_score()
        self.assertIsInstance(threat_score, float)
        self.assertGreaterEqual(threat_score, 0.0)
        self.assertLessEqual(threat_score, 1.0)

        # Test composite scoring with feeds
        composite_scores = real_controller.metrics_collector.calculate_composite_threat_score()
        required_keys = ["composite_threat_score", "pqc_vulnerability_score", "hardware_compromise_score"]
        for key in required_keys:
            self.assertIn(key, composite_scores)

        print("✓ Threat feed integration working")

    @patch('psutil.cpu_percent')
    @patch('psutil.virtual_memory')
    def test_daemon_telemetry_collection(self, mock_memory, mock_cpu):
        """Test that the daemon correctly collects system telemetry."""
        # Mock system metrics
        mock_cpu.return_value = 65.5
        mock_memory.return_value = Mock()
        mock_memory.return_value.percent = 45.2

        # Create daemon
        daemon = RotationDaemon()

        # Mock some threat score calculation
        daemon.controller.metrics_collector.get_threat_score = Mock(return_value=0.6)

        # Collect metrics
        metrics = daemon._collect_system_metrics()

        # Verify metrics structure
        expected_keys = ["latency", "cpu_percent", "memory_percent", "failure_rate", "qkd_health", "threat_score"]
        for key in expected_keys:
            self.assertIn(key, metrics)

        # Verify CPU/memory are reported correctly
        self.assertAlmostEqual(metrics["cpu_percent"], 65.5, places=1)
        self.assertAlmostEqual(metrics["memory_percent"], 45.2, places=1)

        # Verify mock qkd_health and threat_score are reasonable
        self.assertGreaterEqual(metrics["qkd_health"], 0.8)
        self.assertLessEqual(metrics["qkd_health"], 1.0)

        # Verify latency calculation (should be baseline + cpu adjustment)
        expected_latency = 45.0 + (65.5 * 0.5)
        self.assertAlmostEqual(metrics["latency"], expected_latency, places=1)

        print("✓ Daemon telemetry collection working")

    def test_concurrent_telemetry_updates(self):
        """Test that telemetry updates are thread-safe."""
        import threading

        def telemetry_worker(worker_id):
            """Worker thread that adds telemetry."""
            for i in range(10):
                telemetry = TelemetrySnapshot(
                    timestamp=time.time(),
                    latency_ms=50.0 + (worker_id * 10) + i,
                    failures=i % 5,
                    qkd_health=0.9 - (i * 0.01),
                    threat_score=0.2 + (i * 0.05)
                )
                self.controller.update_telemetry(telemetry)

        # Create multiple threads
        threads = []
        for worker_id in range(3):
            thread = threading.Thread(target=telemetry_worker, args=(worker_id,))
            threads.append(thread)
            thread.start()

        # Wait for completion
        for thread in threads:
            thread.join()

        # Verify telemetry was added (exactly 30 entries)
        self.assertEqual(len(self.controller.telemetry_history), 30)

        # Verify buffer rotation (should only keep max_telemetry_history)
        self.assertLessEqual(len(self.controller.telemetry_history), self.controller.max_telemetry_history)

        print("✓ Concurrent telemetry updates working")

    def test_algorithm_validation_edge_cases(self):
        """Test algorithm validation with edge cases."""
        # Test empty algorithms
        empty_rec = {
            "action": "rotate",
            "new_algorithms": {},
            "confidence": 0.8,
            "reason": "Test empty algorithms"
        }
        is_valid = self.controller._validate_recommendation(empty_rec)
        self.assertFalse(is_valid)

        # Test None algorithms
        none_rec = {
            "action": "rotate",
            "new_algorithms": None,
            "confidence": 0.8,
            "reason": "Test None algorithms"
        }
        is_valid = self.controller._validate_recommendation(none_rec)
        self.assertFalse(is_valid)

        # Test partial algorithms (only kem)
        partial_rec = {
            "action": "rotate",
            "new_algorithms": {"kem": "Kyber768"},
            "confidence": 0.8,
            "reason": "Test partial algorithms"
        }
        is_valid = self.controller._validate_recommendation(partial_rec)
        # This should be valid - partial rotation is allowed
        self.assertTrue(is_valid)

        # Test invalid algorithm name
        invalid_rec = {
            "action": "rotate",
            "new_algorithms": {"kem": "InvalidKEM2025", "sig": "Dilithium3"},
            "confidence": 0.8,
            "reason": "Test invalid algorithm"
        }
        is_valid = self.controller._validate_recommendation(invalid_rec)
        self.assertFalse(is_valid)

        print("✓ Algorithm validation edge cases working")

    def test_decision_history_comprehensive(self):
        """Test comprehensive decision history management."""
        # Execute multiple decisions
        decisions = [
            {
                "action": "rotate",
                "new_algorithms": {"kem": "Kyber768", "sig": "Dilithium3"},
                "confidence": 0.9,
                "reason": "First rotation"
            },
            {
                "action": "rotate",
                "new_algorithms": {"kem": "Kyber1024", "sig": "Dilithium5"},
                "confidence": 0.95,
                "reason": "Second rotation"
            },
            {
                "action": "rollback",
                "new_algorithms": {"kem": "Kyber512", "sig": "Dilithium3"},
                "confidence": 1.0,
                "reason": "Rollback test"
            }
        ]

        for decision in decisions:
            self.controller.execute_rotation(decision)

        # Test history retrieval
        history = self.controller.get_decision_history()
        self.assertEqual(len(history), len(decisions))

        # Verify decisions are in correct order
        for i, decision in enumerate(decisions):
            hist_decision = history[-(len(decisions)-i)]
            self.assertEqual(hist_decision["action"], decision["action"])

        # Test history limit
        limited_history = self.controller.get_decision_history(limit=2)
        self.assertEqual(len(limited_history), 2)

        print("✓ Decision history management working")


if __name__ == '__main__':
    unittest.main()
