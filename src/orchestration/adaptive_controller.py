"""
Adaptive Cryptography Orchestration Core

This module implements the core orchestration logic for autonomous, policy-driven
cryptographic algorithm rotation and security adaptations in QASP v2.0.

Features:
- Real-time threat surface evaluation
- AI-driven policy recommendations
- Dynamic algorithm rotation without downtime
- Threat-score weighted decision making
- Automated rollback on performance degradation
"""

import json
import sys
import time
import asyncio
import threading
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from datetime import datetime
import psutil
import os
from pathlib import Path


@dataclass
class TelemetrySnapshot:
    """Snapshot of current system telemetry metrics."""
    timestamp: float
    latency_ms: float
    failures: int
    qkd_health: float  # 0.0 to 1.0
    threat_score: float  # 0.0 to 1.0


@dataclass
class PolicyDecision:
    """Represents a security policy decision."""
    timestamp: datetime
    action: str  # 'rotate', 'maintain', 'rollback'
    reason: str
    new_algorithms: Optional[Dict[str, str]]
    prev_algorithms: Optional[Dict[str, str]]
    decision_confidence: float


class AdaptiveController:
    """
    Orchestrates adaptive cryptography operations based on real-time telemetry,
    threat intelligence, and AI-driven policy recommendations.
    """

    def __init__(self, policy_agent=None, metrics_collector=None):
        self.policy_agent = policy_agent
        self.metrics_collector = metrics_collector

        # Current algorithm state
        self.current_kem = os.getenv("KEM_ALG", "Kyber512")
        self.current_sig = os.getenv("SIG_ALG", "Dilithium3")

        # Decision history
        self.decision_log: List[PolicyDecision] = []

        # Telemetry buffer
        self.telemetry_history: List[TelemetrySnapshot] = []
        self.max_telemetry_history = 100

        # Lock for thread-safe operations
        self._lock = threading.Lock()

        # Policy weights (configurable)
        self.policy_weights = {
            'latency_threshold': 100,  # ms
            'failure_rate_threshold': 0.01,  # 1%
            'threat_score_threshold': 0.7,  # 70%
            'qkd_health_threshold': 0.8,  # 80%
        }

    def load_policy_weights(self, weights: Dict[str, float]):
        """Update policy decision weights."""
        self.policy_weights.update(weights)

    def update_telemetry(self, telemetry: TelemetrySnapshot):
        """Update internal telemetry history."""
        with self._lock:
            self.telemetry_history.append(telemetry)
            if len(self.telemetry_history) > self.max_telemetry_history:
                self.telemetry_history.pop(0)

    def evaluate_threat_surface(self) -> Dict[str, Any]:
        """
        Evaluate current threat surface based on telemetry and feeds.

        Returns:
            Dict containing evaluation results and triggering factors.
        """
        if not self.telemetry_history:
            return {"threat_level": "insufficient_data", "triggers": []}

        latest = self.telemetry_history[-1]

        triggers = []

        # Evaluate against thresholds
        if latest.latency_ms > self.policy_weights['latency_threshold']:
            triggers.append(f"latency_{latest.latency_ms}ms")

        if len(self.telemetry_history) >= 10:  # Need some history
            recent_failures = sum(s.failures for s in self.telemetry_history[-10:])
            failure_rate = recent_failures / len(self.telemetry_history[-10:])
            if failure_rate > self.policy_weights['failure_rate_threshold']:
                triggers.append(f"failure_rate_{failure_rate:.3f}")

        if latest.threat_score > self.policy_weights['threat_score_threshold']:
            triggers.append(f"threat_score_{latest.threat_score:.2f}")

        if latest.qkd_health < self.policy_weights['qkd_health_threshold']:
            triggers.append(f"qkd_health_{latest.qkd_health:.2f}")

        # Determine threat level
        if len(triggers) >= 3:
            threat_level = "critical"
        elif len(triggers) >= 2:
            threat_level = "high"
        elif len(triggers) >= 1:
            threat_level = "medium"
        else:
            threat_level = "low"

        return {
            "threat_level": threat_level,
            "triggers": triggers,
            "timestamp": latest.timestamp,
            "metrics": {
                "latency": latest.latency_ms,
                "threat_score": latest.threat_score,
                "qkd_health": latest.qkd_health,
                "failure_rate": failure_rate if 'failure_rate' in locals() else 0.0
            }
        }

    def recommend_algorithm_change(self, threat_evaluation: Dict[str, Any]) -> Dict[str, Any]:
        """
        Recommend algorithm changes based on threat evaluation.

        Returns:
            Dict with recommendations and confidence scores.
        """
        current_algorithms = {
            "kem": self.current_kem,
            "sig": self.current_sig
        }

        # Default recommendation - no change
        recommendation = {
            "action": "maintain",
            "new_algorithms": None,
            "reason": "No threat triggers detected",
            "confidence": 0.95,
            "current_algorithms": current_algorithms
        }

        if threat_evaluation["threat_level"] == "low":
            return recommendation

        # AI-based decision making if agent available
        if self.policy_agent:
            try:
                ai_recommendation = self.policy_agent.get_policy_recommendation(
                    threat_evaluation,
                    current_algorithms
                )
                if ai_recommendation:
                    # Validate AI recommendation
                    if self._validate_recommendation(ai_recommendation):
                        recommendation.update(ai_recommendation)
                        recommendation["reason"] = f"AI recommendation: {ai_recommendation.get('reason', 'Unknown')}"
            except Exception as e:
                # Fallback to rule-based logic
                print(f"AI decision failed, using rule-based logic: {e}")

        # Rule-based fallback
        recommendation = self._rule_based_recommendation(threat_evaluation, current_algorithms)

        return recommendation

    def _rule_based_recommendation(self, threat_eval: Dict[str, Any], current: Dict[str, str]) -> Dict[str, Any]:
        """Fallback rule-based algorithm recommendation."""
        action = "maintain"
        new_alg = None
        confidence = 0.8

        # Simple escalation logic
        if threat_eval["threat_level"] in ["high", "critical"]:
            # Escalate to stronger algorithms
            if current["kem"] == "Kyber512":
                new_alg = {"kem": "Kyber768", "sig": "Dilithium3"}
                action = "rotate"
            elif current["kem"] == "Kyber768":
                new_alg = {"kem": "Kyber1024", "sig": "Dilithium5"}
                action = "rotate"

        return {
            "action": action,
            "new_algorithms": new_alg,
            "reason": f"Rule-based: {threat_eval['threat_level']} threat level",
            "confidence": confidence,
            "current_algorithms": current
        }

    def _validate_recommendation(self, recommendation: Dict[str, Any]) -> bool:
        """Validate algorithm recommendation for safety."""
        # Basic validation - ensure algorithms are supported
        from src.config.crypto_config import SUPPORTED_KEM_ALGORITHMS, SUPPORTED_SIGNATURE_ALGORITHMS

        new_alg = recommendation.get("new_algorithms")
        if new_alg:
            if new_alg.get("kem") and new_alg["kem"] not in SUPPORTED_KEM_ALGORITHMS:
                return False
            if new_alg.get("sig") and new_alg["sig"] not in SUPPORTED_SIGNATURE_ALGORITHMS:
                return False

        return True

    def execute_rotation(self, recommendation: Dict[str, Any]) -> bool:
        """
        Execute algorithm rotation if recommended.

        Returns:
            True if rotation successful, False otherwise.
        """
        if recommendation["action"] != "rotate":
            return True  # No rotation needed

        new_algorithms = recommendation["new_algorithms"]
        if not new_algorithms:
            return False

        print(f"Executing algorithm rotation: {new_algorithms}")

        # Environment variable updates (runtime rotation)
        prev_algorithms = {"kem": self.current_kem, "sig": self.current_sig}

        updates = []
        if "kem" in new_algorithms:
            os.environ["KEM_ALG"] = new_algorithms["kem"]
            self.current_kem = new_algorithms["kem"]
            updates.append(f"KEM_ALG={new_algorithms['kem']}")

        if "sig" in new_algorithms:
            os.environ["SIG_ALG"] = new_algorithms["sig"]
            self.current_sig = new_algorithms["sig"]
            updates.append(f"SIG_ALG={new_algorithms['sig']}")

        # Log the decision (persists across restarts)
        decision = PolicyDecision(
            timestamp=datetime.now(),
            action="rotate",
            reason=recommendation["reason"],
            new_algorithms=new_algorithms,
            prev_algorithms=prev_algorithms,
            decision_confidence=recommendation["confidence"]
        )
        self.log_policy_decision(decision)

        print(f"Algorithm rotation completed: {updates}")

        # Update affected modules by re-importing (rolling reload)
        try:
            # Force reload of configuration modules
            import importlib
            if "config.crypto_config" in sys.modules:
                importlib.reload(sys.modules["config.crypto_config"])
            if "qasp.crypto" in sys.modules:
                importlib.reload(sys.modules["qasp.crypto"])

            return True
        except Exception as e:
            print(f"Error during rolling reload: {e}")
            # Attempt rollback
            self._rollback_rotation(prev_algorithms, recommendation)
            return False

    def _rollback_rotation(self, prev_algorithms: Dict[str, str], decision: Dict[str, Any]):
        """Rollback to previous algorithm set."""
        print("Rolling back algorithm rotation")

        if "kem" in prev_algorithms:
            os.environ["KEM_ALG"] = prev_algorithms["kem"]
            self.current_kem = prev_algorithms["kem"]

        if "sig" in prev_algorithms:
            os.environ["SIG_ALG"] = prev_algorithms["sig"]
            self.current_sig = prev_algorithms["sig"]

        # Log rollback
        rollback_decision = PolicyDecision(
            timestamp=datetime.now(),
            action="rollback",
            reason="Automatic rollback due to rotation failure",
            new_algorithms=prev_algorithms,
            prev_algorithms=decision.get("new_algorithms"),
            decision_confidence=1.0
        )
        self.log_policy_decision(rollback_decision)

    def log_policy_decision(self, decision: PolicyDecision):
        """Log policy decision to persistent storage."""
        with self._lock:
            self.decision_log.append(decision)

        # Also write to disk
        log_path = Path("reports/policy_decisions.json")
        log_path.parent.mkdir(parents=True, exist_ok=True)

        # Read existing log
        if log_path.exists():
            with open(log_path, 'r') as f:
                existing = json.load(f)
        else:
            existing = {"decisions": []}

        # Add new decision
        decision_dict = {
            "timestamp": decision.timestamp.isoformat(),
            "action": decision.action,
            "reason": decision.reason,
            "new_algorithms": decision.new_algorithms,
            "prev_algorithms": decision.prev_algorithms,
            "confidence": decision.decision_confidence
        }
        existing["decisions"].append(decision_dict)

        # Write back
        with open(log_path, 'w') as f:
            json.dump(existing, f, indent=2)

    def get_decision_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent policy decisions."""
        return [
            {
                "timestamp": d.timestamp.isoformat(),
                "action": d.action,
                "reason": d.reason,
                "algorithms": d.new_algorithms or d.prev_algorithms,
                "confidence": d.decision_confidence
            }
            for d in self.decision_log[-limit:]
        ]

    def get_current_policy_state(self) -> Dict[str, Any]:
        """Get current policy state for API endpoints."""
        latest_eval = self.evaluate_threat_surface()

        return {
            "timestamp": datetime.now().isoformat(),
            "current_algorithms": {
                "kem": self.current_kem,
                "signature": self.current_sig
            },
            "threat_evaluation": latest_eval,
            "last_decision": self.get_decision_history(1)[0] if self.decision_log else None
        }
