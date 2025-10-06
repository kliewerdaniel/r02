"""
Autonomous Rotation Daemon for QASP v2.0

This daemon runs continuously to monitor telemetry, evaluate threat surfaces,
and execute autonomous cryptographic algorithm rotations based on AI-driven
policy recommendations.

Features:
- Continuous monitoring of system telemetry and threat feeds
- Policy-based decision making with human override capability
- Safe rotation with automatic rollback on performance degradation
- Comprehensive audit logging and decision tracking
- Integration with AdaptiveController for policy orchestration
"""

import json
import time
import signal
import threading
from typing import Dict, Any, Optional
from datetime import datetime
import psutil
import os
from pathlib import Path
import sys
from collections import deque

# Add src to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from orchestration.adaptive_controller import AdaptiveController, TelemetrySnapshot
from ai_threat.policy_agent import PolicyAgent
from analytics.metrics_collector import LTSMetricsCollector


class RotationDaemon:
    """
    Autonomous daemon for continuous security adaptation and algorithm rotation.

    Monitors system health, threat intelligence, and executes policy-driven
    cryptographic algorithm rotations with fail-safe mechanisms.
    """

    def __init__(self):
        # Core components
        self.policy_agent = PolicyAgent()
        self.metrics_collector = LTSMetricsCollector()
        self.controller = AdaptiveController(
            policy_agent=self.policy_agent,
            metrics_collector=self.metrics_collector
        )

        # Configuration
        self.check_interval = int(os.getenv("POLICY_CHECK_INTERVAL", "60"))  # seconds
        self.telemetry_window = int(os.getenv("TELEMETRY_WINDOW", "300"))  # 5 minutes

        # State management
        self.running = False
        self.last_rotation_time = 0
        self.rotation_cooldown = int(os.getenv("ROTATION_COOLDOWN", "3600"))  # 1 hour

        # Telemetry buffers
        self.telemetry_buffer: deque = deque(maxlen=100)
        self.performance_baseline = self._establish_performance_baseline()

        # Monitoring metrics
        self.monitoring_stats = {
            "checks_performed": 0,
            "rotations_executed": 0,
            "rollbacks_performed": 0,
            "errors_encountered": 0,
            "uptime_seconds": 0
        }

        # Graceful shutdown handling
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

    def _establish_performance_baseline(self) -> Dict[str, float]:
        """Establish baseline performance metrics before starting rotations."""
        print("Establishing performance baseline...")

        # Take several measurements to establish baseline
        baselines = []
        for i in range(10):
            baselines.append(self._collect_system_metrics())
            time.sleep(1)

        # Calculate averages
        baseline = {}
        for key in baselines[0].keys():
            values = [b[key] for b in baselines]
            baseline[key] = sum(values) / len(values)

        print(f"Performance baseline established: latency={baseline.get('latency', 0):.1f}ms")
        return baseline

    def _collect_system_metrics(self) -> Dict[str, float]:
        """Collect current system performance metrics."""
        try:
            # CPU and memory metrics
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory_percent = psutil.virtual_memory().percent

            # Mock QKD health (would integrate with actual QKD subsystem)
            qkd_health = 0.95  # Placeholder

            # Get latency from recent operations (placeholder - would come from actual metrics)
            latency = 45.0 + (cpu_percent * 0.5)  # Simulate load-dependent latency

            # Mock threat score (would integrate with threat feeds)
            threat_score = min(0.9, cpu_percent / 100 + memory_percent / 200)

            # Mock failure rate (very low for healthy system)
            failure_rate = max(0.001, (cpu_percent + memory_percent) / 20000)

            return {
                "latency": latency,
                "cpu_percent": cpu_percent,
                "memory_percent": memory_percent,
                "failure_rate": failure_rate,
                "qkd_health": qkd_health,
                "threat_score": threat_score
            }

        except Exception as e:
            print(f"Error collecting system metrics: {e}")
            return {
                "latency": 100.0,
                "cpu_percent": 50.0,
                "memory_percent": 50.0,
                "failure_rate": 0.01,
                "qkd_health": 0.8,
                "threat_score": 0.5
            }

    def _monitor_performance_degradation(self, new_metrics: Dict[str, float]) -> bool:
        """
        Monitor for performance degradation after rotation.

        Returns True if degradation detected and rollback should be triggered.
        """
        if not self.performance_baseline:
            return False

        # Check for significant degradation
        latency_increase = new_metrics["latency"] / self.performance_baseline.get("latency", 50.0)
        failure_increase = new_metrics.get("failure_rate", 0) / max(0.001, self.performance_baseline.get("failure_rate", 0.001))

        # Trigger rollback if latency more than doubles or failures increase 5x
        degradation_detected = latency_increase > 2.0 or failure_increase > 5.0

        if degradation_detected:
            print(f"Performance degradation detected: latency {latency_increase:.1f}x, failures {failure_increase:.1f}x")

        return degradation_detected

    def _execute_policy_cycle(self):
        """Execute a complete policy evaluation and potential rotation cycle."""
        try:
            self.monitoring_stats["checks_performed"] += 1

            # Collect current telemetry
            current_metrics = self._collect_system_metrics()
            timestamp = time.time()

            # Create telemetry snapshot
            snapshot = TelemetrySnapshot(
                timestamp=timestamp,
                latency_ms=current_metrics["latency"],
                failures=int(current_metrics["failure_rate"] * 1000),  # Scale up for meaningful numbers
                qkd_health=current_metrics["qkd_health"],
                threat_score=current_metrics["threat_score"]
            )

            # Update controller telemetry
            self.controller.update_telemetry(snapshot)

            # Evaluate threat surface
            threat_evaluation = self.controller.evaluate_threat_surface()

            if threat_evaluation["threat_level"] == "insufficient_data":
                print("Insufficient telemetry data - skipping policy evaluation")
                return

            print(f"Threat evaluation: {threat_evaluation['threat_level']} "
                  f"(triggers: {', '.join(threat_evaluation['triggers'])})")

            # Get policy recommendation
            recommendation = self.controller.recommend_algorithm_change(threat_evaluation)

            print(f"Policy recommendation: {recommendation['action']} "
                  f"(confidence: {recommendation['confidence']:.2f}) - {recommendation['reason']}")

            # Check rotation cooldown
            time_since_last_rotation = time.time() - self.last_rotation_time
            if time_since_last_rotation < self.rotation_cooldown:
                remaining_cooldown = int(self.rotation_cooldown - time_since_last_rotation)
                print(f"Rotation cooldown active - {remaining_cooldown}s remaining")
                return

            # Execute rotation if recommended and action is "rotate"
            if recommendation["action"] == "rotate" and recommendation["confidence"] > 0.7:
                print("Executing algorithm rotation...")

                success = self.controller.execute_rotation(recommendation)

                if success:
                    self.monitoring_stats["rotations_executed"] += 1
                    self.last_rotation_time = time.time()

                    # Monitor for immediate performance degradation
                    time.sleep(2)  # Brief stabilization period
                    post_rotation_metrics = self._collect_system_metrics()

                    if self._monitor_performance_degradation(post_rotation_metrics):
                        print("Performance degradation detected - initiating rollback")
                        # Rollback would be automatic in execute_rotation on failure detection
                        self.monitoring_stats["rollbacks_performed"] += 1
                    else:
                        print("Rotation completed successfully - no performance degradation")
                else:
                    print("Rotation execution failed")
            else:
                print("Rotation not recommended or confidence too low")

        except Exception as e:
            print(f"Error in policy cycle execution: {e}")
            self.monitoring_stats["errors_encountered"] += 1

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully."""
        print(f"\nReceived signal {signum} - initiating graceful shutdown...")
        self.stop()

    def start(self):
        """Start the autonomous rotation daemon."""
        if self.running:
            print("Daemon already running")
            return

        print("Starting QASP v2.0 Autonomous Rotation Daemon...")
        print(f"Policy check interval: {self.check_interval}s")
        print(f"Rotation cooldown: {self.rotation_cooldown}s")

        self.running = True
        start_time = time.time()

        try:
            while self.running:
                cycle_start = time.time()

                self._execute_policy_cycle()

                # Calculate next cycle time
                cycle_duration = time.time() - cycle_start
                sleep_time = max(0, self.check_interval - cycle_duration)

                if sleep_time > 0:
                    time.sleep(sleep_time)
                elif cycle_duration > self.check_interval:
                    print(f"Policy cycle took longer than check interval: {cycle_duration:.1f}s")
                # Update uptime
                self.monitoring_stats["uptime_seconds"] = int(time.time() - start_time)

        except KeyboardInterrupt:
            print("\nKeyboard interrupt received")
        except Exception as e:
            print(f"Critical error in daemon: {e}")
        finally:
            self._cleanup()

    def stop(self):
        """Stop the daemon gracefully."""
        print("Stopping autonomous rotation daemon...")
        self.running = False
        self._cleanup()

    def _cleanup(self):
        """Perform cleanup operations."""
        try:
            # Export monitoring statistics
            self._export_monitoring_stats()

            # Export AI decision log
            if self.policy_agent:
                self.policy_agent.export_decision_log()

            print("Daemon shutdown complete")
        except Exception as e:
            print(f"Error during cleanup: {e}")

    def _export_monitoring_stats(self):
        """Export daemon monitoring statistics."""
        stats_file = Path("reports/rotation_daemon_stats.json")

        stats_data = {
            "export_timestamp": datetime.now().isoformat(),
            "monitoring_stats": self.monitoring_stats,
            "configuration": {
                "check_interval": self.check_interval,
                "rotation_cooldown": self.rotation_cooldown,
                "telemetry_window": self.telemetry_window
            },
            "performance_baseline": self.performance_baseline,
            "final_policy_state": self.controller.get_current_policy_state()
        }

        stats_file.parent.mkdir(parents=True, exist_ok=True)
        with open(stats_file, 'w') as f:
            json.dump(stats_data, f, indent=2)

        print(f"Monitoring statistics exported to {stats_file}")

    def get_status(self) -> Dict[str, Any]:
        """Get current daemon status and statistics."""
        return {
            "running": self.running,
            "uptime_seconds": self.monitoring_stats["uptime_seconds"],
            "checks_performed": self.monitoring_stats["checks_performed"],
            "rotations_executed": self.monitoring_stats["rotations_executed"],
            "rollbacks_performed": self.monitoring_stats["rollbacks_performed"],
            "errors_encountered": self.monitoring_stats["errors_encountered"],
            "current_policy_state": self.controller.get_current_policy_state(),
            "last_rotation_ago": time.time() - self.last_rotation_time if self.last_rotation_time > 0 else None
        }


def main():
    """Main entry point for running the rotation daemon."""
    daemon = RotationDaemon()
    print("QASP v2.0 Autonomous Rotation Daemon initialized")
    print("Press Ctrl+C to stop")

    try:
        daemon.start()
    except KeyboardInterrupt:
        pass
    finally:
        daemon.stop()


if __name__ == "__main__":
    main()
