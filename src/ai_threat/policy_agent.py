"""
AI-Driven Policy Agent for QASP v2.0

This module implements an intelligent policy agent that uses local LLM capabilities
to reason about cryptographic algorithm rotation decisions based on threat intelligence,
telemetry data, and policy constraints.

Features:
- LLM-powered policy reasoning (Ollama/SmolAgents compatible)
- Risk-weighted decision making
- Context-aware algorithm recommendations
- Explainable AI reasoning traces
"""

import json
import requests
import os
from typing import Dict, Any, Optional, List
from datetime import datetime
from pathlib import Path
import subprocess


class PolicyAgent:
    """
    AI agent for autonomous security policy decision making.

    Uses local LLM for reasoning about cryptographic algorithm rotations
    in response to threat intelligence and telemetry signals.
    """

    def __init__(self):
        # LLM configuration
        self.llm_endpoint = os.getenv("LLM_ENDPOINT", "http://localhost:11434/api/generate")
        self.llm_model = os.getenv("LLM_MODEL", "qwen2.5-coder:7b")
        self.temperature = float(os.getenv("LLM_TEMPERATURE", "0.3"))

        # Policy constraints
        self.max_risk_tolerance = float(os.getenv("MAX_RISK_TOLERANCE", "0.7"))
        self.min_confidence_threshold = float(os.getenv("MIN_CONFIDENCE_THRESHOLD", "0.8"))

        # Context storage
        self.decision_context = []
        self.max_context_history = 10

        # Algorithm knowledge base
        self.algorithm_profiles = self._load_algorithm_profiles()

    def _load_algorithm_profiles(self) -> Dict[str, Dict[str, Any]]:
        """Load algorithm security and performance profiles."""
        return {
            "Kyber512": {
                "security_level": 1,
                "performance_index": 95,  # relative speed score
                "quantum_resistance": "high",
                "description": "NIST Level 1 KEM - balanced security and performance"
            },
            "Kyber768": {
                "security_level": 3,
                "performance_index": 75,
                "quantum_resistance": "very_high",
                "description": "NIST Level 3 KEM - enhanced security for sensitive applications"
            },
            "Kyber1024": {
                "security_level": 5,
                "performance_index": 50,
                "quantum_resistance": "maximum",
                "description": "NIST Level 5 KEM - maximum security for critical infrastructure"
            },
            "Dilithium2": {
                "security_level": 2,
                "performance_index": 90,
                "quantum_resistance": "high",
                "description": "NIST Level 2 signature - fast verification for general use"
            },
            "Dilithium3": {
                "security_level": 3,
                "performance_index": 80,
                "quantum_resistance": "very_high",
                "description": "NIST Level 3 signature - balanced security and speed"
            },
            "Dilithium5": {
                "security_level": 5,
                "performance_index": 60,
                "quantum_resistance": "maximum",
                "description": "NIST Level 5 signature - maximum security for compliance"
            },
            "Falcon-512": {
                "security_level": 1,
                "performance_index": 98,
                "quantum_resistance": "high",
                "description": "Fast lattice-based signature for performance-critical apps"
            }
        }

    def _is_llm_available(self) -> bool:
        """Check if LLM service is available."""
        try:
            # Try to connect to the LLM endpoint
            response = requests.get(self.llm_endpoint.replace("/api/generate", "/api/tags"),
                                  timeout=5)
            if response.status_code == 200:
                models = response.json().get("models", [])
                model_names = [m["name"] for m in models]
                return self.llm_model in model_names or any(self.llm_model.split(":")[0] in name for name in model_names)
        except Exception:
            pass

        # Fallback: check if ollama process is running
        try:
            result = subprocess.run(["pgrep", "-f", "ollama"], capture_output=True, text=True)
            return result.returncode == 0
        except FileNotFoundError:
            pass

        return False

    def _build_policy_prompt(self, threat_evaluation: Dict[str, Any],
                           current_algorithms: Dict[str, str]) -> str:
        """Construct LLM prompt for policy decision making."""

        threat_level = threat_evaluation["threat_level"]
        triggers = threat_evaluation["triggers"]
        metrics = threat_evaluation.get("metrics", {})

        # Build context from recent decisions
        recent_decisions = "\n".join([
            f"- {ctx.get('timestamp', 'Unknown')}: {ctx.get('action', 'Unknown')} - {ctx.get('reason', 'Unknown')}"
            for ctx in self.decision_context[-3:]
        ]) or "None"

        # Available algorithms summary
        kem_options = ["Kyber512", "Kyber768", "Kyber1024", "FrodoKEM-640-AES"]
        sig_options = ["Dilithium2", "Dilithium3", "Dilithium5", "Falcon-512"]

        prompt = f"""You are an expert cryptographic security policy advisor for QASP v2.0, an autonomous post-quantum cryptographic system. You must make intelligent algorithm rotation decisions based on threat intelligence and system telemetry.

CURRENT SITUATION:
- Threat Level: {threat_level.upper()}
- Triggering Factors: {', '.join(triggers)}
- System Metrics:
  - Latency: {metrics.get('latency', 'unknown')}ms
  - Threat Score: {metrics.get('threat_score', 'unknown')}
  - QKD Health: {metrics.get('qkd_health', 'unknown')}
  - Failure Rate: {metrics.get('failure_rate', 'unknown')}

CURRENT ALGORITHMS:
- KEM: {current_algorithms['kem']}
- Signature: {current_algorithms['sig']}

AVAILABLE ALGORITHMS (KEM):
{chr(10).join([f"- {alg}: Level {self.algorithm_profiles.get(alg, {}).get('security_level', '?')} security, {self.algorithm_profiles.get(alg, {}).get('performance_index', '?')} speed score" for alg in kem_options])}

AVAILABLE ALGORITHMS (Signature):
{chr(10).join([f"- {alg}: Level {self.algorithm_profiles.get(alg, {}).get('security_level', '?')} security, {self.algorithm_profiles.get(alg, {}).get('performance_index', '?')} speed score" for alg in sig_options])}

RECENT DECISIONS:
{recent_decisions}

INSTRUCTION:
Based on the threat level and system metrics, recommend whether to ROTATE algorithms, MAINTAIN current, or initiate ROLLBACK.

Consider:
1. Security requirements based on threat level (LOW=maintain, MEDIUM/HIGH=consider upgrade, CRITICAL=aggressive upgrade)
2. Performance impact of algorithm changes
3. Risk tolerance for operations ({self.max_risk_tolerance} max)
4. Historical decision patterns

RESPONSE FORMAT (JSON only):
{{
    "action": "rotate"|"maintain"|"rollback",
    "new_algorithms": {{"kem": "algorithm_name", "sig": "algorithm_name"}} | null,
    "confidence": 0.0-1.0,
    "reason": "Brief explanation of decision (max 100 chars)",
    "risk_assessment": "low"|"medium"|"high"|"critical"
}}

If action is "maintain", set new_algorithms to null.
If action is "rollback", specify the previous algorithms you want to restore.
Ensure the response is valid JSON only.
"""

        return prompt

    def _parse_llm_response(self, response_text: str) -> Dict[str, Any]:
        """Parse and validate LLM response JSON."""
        try:
            # Extract JSON from response (LLM might add extra text)
            start = response_text.find('{')
            end = response_text.rfind('}') + 1
            if start >= 0 and end > start:
                json_str = response_text[start:end]
                result = json.loads(json_str)

                # Validate required fields
                required_fields = ["action", "new_algorithms", "confidence", "reason"]
                if not all(field in result for field in required_fields):
                    raise ValueError("Missing required fields in LLM response")

                # Validate confidence threshold
                if result["confidence"] < self.min_confidence_threshold:
                    result["action"] = "maintain"
                    result["reason"] = "Confidence too low - maintaining current algorithms"

                return result
            else:
                raise ValueError("No JSON found in LLM response")

        except (json.JSONDecodeError, ValueError) as e:
            print(f"LLM response parsing failed: {e}")
            print(f"Raw response: {response_text}")
            # Return safe fallback
            return {
                "action": "maintain",
                "new_algorithms": None,
                "confidence": 0.5,
                "reason": "LLM response parsing failed - safe fallback",
                "risk_assessment": "medium"
            }

    def _query_llm(self, prompt: str) -> str:
        """Query the local LLM for policy recommendations."""
        payload = {
            "model": self.llm_model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": self.temperature,
                "num_predict": 200
            }
        }

        try:
            response = requests.post(self.llm_endpoint, json=payload, timeout=30)
            response.raise_for_status()

            result = response.json()
            return result.get("response", "").strip()

        except Exception as e:
            print(f"LLM query failed: {e}")
            return '{"action": "maintain", "new_algorithms": null, "confidence": 0.0, "reason": "LLM query failed", "risk_assessment": "high"}'

    def get_policy_recommendation(self, threat_evaluation: Dict[str, Any],
                                current_algorithms: Dict[str, str]) -> Optional[Dict[str, Any]]:
        """
        Get AI-powered policy recommendation for algorithm rotation.

        Returns:
            Dict with action, new_algorithms, confidence, and reasoning
        """
        if not self._is_llm_available():
            print("LLM not available - skipping AI recommendation")
            return None

        # Build decision context
        prompt = self._build_policy_prompt(threat_evaluation, current_algorithms)

        # Query LLM
        llm_response = self._query_llm(prompt)

        # Parse and validate response
        recommendation = self._parse_llm_response(llm_response)

        # Store context for future decisions
        decision_context = {
            "timestamp": datetime.now().isoformat(),
            "threat_level": threat_evaluation["threat_level"],
            "action": recommendation["action"],
            "reason": recommendation["reason"],
            "confidence": recommendation["confidence"]
        }
        self.decision_context.append(decision_context)
        if len(self.decision_context) > self.max_context_history:
            self.decision_context.pop(0)

        return recommendation

    def get_decision_explanation(self, recommendation: Dict[str, Any]) -> str:
        """Provide human-readable explanation of policy recommendation."""
        action = recommendation["action"]
        confidence = recommendation["confidence"]
        reason = recommendation["reason"]
        risk = recommendation.get("risk_assessment", "unknown")

        if action == "rotate":
            new_kem = recommendation["new_algorithms"].get("kem", "unknown")
            new_sig = recommendation["new_algorithms"].get("sig", "unknown")
            return f"ROTATION RECOMMENDED ({confidence:.1%} confidence): {reason}. New algorithms: KEM={new_kem}, SIG={new_sig}. Risk: {risk}."
        elif action == "rollback":
            return f"ROLLBACK RECOMMENDED ({confidence:.1%} confidence): {reason}. Risk: {risk}."
        else:
            return f"MAINTAIN CURRENT ({confidence:.1%} confidence): {reason}. Risk: {risk}."

    def export_decision_log(self, filepath: str = "reports/ai_policy_log.json"):
        """Export AI decision history for analysis."""
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)

        log_data = {
            "export_timestamp": datetime.now().isoformat(),
            "decision_history": self.decision_context,
            "llm_config": {
                "endpoint": self.llm_endpoint,
                "model": self.llm_model,
                "temperature": self.temperature
            }
        }

        with open(filepath, 'w') as f:
            json.dump(log_data, f, indent=2)
