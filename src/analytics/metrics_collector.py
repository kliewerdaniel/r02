"""
LTS Analytics Collector

Aggregates QASP usage metrics for LTS maintenance and reporting.
Collects multi-tenant usage stats, key-rotation frequency, algorithm adoption,
and integrates threat intelligence feeds for composite threat scoring.
"""

import json
import time
import os
from collections import defaultdict
from typing import Dict, List, Optional
from pathlib import Path
from datetime import datetime

from src.telemetry.metrics import HANDSHAKE_TOTAL, KEY_OPERATIONS_TOTAL, registry


class LTSMetricsCollector:
    def __init__(self):
        self.usage_data = defaultdict(dict)
        self.start_time = time.time()

    def collect_usage_stats(self) -> Dict:
        """Aggregate current metrics."""
        # Simulate collection (in real: query Prometheus or DB)
        handshake_counts = defaultdict(int)
        key_ops = defaultdict(int)

        # Gather from existing counters (simulated)
        # In practice, integrate with Prometheus API or persistent storage
        tenant_usage = {}

        for tenant in ['tenant_1', 'tenant_2', 'default']:  # Mock tenants
            tenant_usage[tenant] = {
                'handshakes_total': handshake_counts[tenant],
                'key_rotations': key_ops.get('rotate', 0),
                'algorithm_adoption': {
                    'kyber768': 60,  # percentage
                    'ml-kem-1024': 40,
                },
                'failover_events': 2,
            }

        return {
            'collection_timestamp': time.time(),
            'uptime_seconds': time.time() - self.start_time,
            'tenant_usage': tenant_usage,
            'global_stats': {
                'total_tenants': len(tenant_usage),
                'total_handshakes': sum(u['handshakes_total'] for u in tenant_usage.values()),
                'total_key_rotations': sum(u['key_rotations'] for u in tenant_usage.values()),
            }
        }

    def load_threat_feeds(self) -> Dict[str, Dict]:
        """Load and parse threat intelligence feeds."""
        threat_feeds_path = Path("../../threat_feeds")  # Relative to src/analytics/
        current_dir = Path(__file__).parent

        # Try multiple possible paths for threat_feeds
        possible_paths = [
            current_dir.parent / "threat_feeds",
            Path.cwd() / "threat_feeds",
            threat_feeds_path
        ]

        feeds = {}
        feed_files = ["pqc_vulnerabilities.json", "hardware_incidents.json", "network_events.json"]

        for path in possible_paths:
            if path.exists():
                for feed_file in feed_files:
                    feed_path = path / feed_file
                    if feed_path.exists():
                        try:
                            with open(feed_path, 'r') as f:
                                feed_name = feed_file.split('.')[0]
                                feeds[feed_name] = json.load(f)
                        except Exception as e:
                            print(f"Error loading threat feed {feed_file}: {e}")
                break

        if not feeds:
            print("Warning: No threat feeds found, using default values")

        return feeds

    def calculate_composite_threat_score(self) -> Dict[str, float]:
        """
        Calculate composite threat score from multiple intelligence feeds.

        Returns:
            Dict containing threat metrics and composite scores.
        """
        feeds = self.load_threat_feeds()

        # Default scores if feeds unavailable
        default_scores = {
            "pqc_vulnerability_score": 0.3,
            "hardware_compromise_score": 0.4,
            "network_attack_score": 0.5,
            "composite_threat_score": 0.4
        }

        if not feeds:
            return default_scores

        # Extract threat scores from feeds
        scores = {}

        # PQC vulnerabilities
        pqc_feed = feeds.get("pqc_vulnerabilities", {})
        pqc_global_level = pqc_feed.get("global_threat_level", "LOW")
        pqc_level_map = {"LOW": 0.2, "MEDIUM": 0.5, "HIGH": 0.8, "CRITICAL": 0.95}
        scores["pqc_vulnerability_score"] = pqc_level_map.get(pqc_global_level, 0.3)

        # Hardware incidents
        hw_feed = feeds.get("hardware_incidents", {})
        hw_global_level = hw_feed.get("global_hardware_threat_level", "MEDIUM")
        hw_level_map = {"LOW": 0.2, "MEDIUM": 0.5, "HIGH": 0.8, "CRITICAL": 0.95}
        scores["hardware_compromise_score"] = hw_level_map.get(hw_global_level, 0.4)

        # Network events
        net_feed = feeds.get("network_events", {})
        net_global_level = net_feed.get("global_network_threat_level", "HIGH")
        net_level_map = {"LOW": 0.2, "MEDIUM": 0.5, "HIGH": 0.8, "CRITICAL": 0.95}
        scores["network_attack_score"] = net_level_map.get(net_global_level, 0.5)

        # Calculate weighted composite score
        # Weights based on impact: network attacks have highest weight as they affect all communications
        weights = {
            "pqc_vulnerability_score": 0.3,
            "hardware_compromise_score": 0.3,
            "network_attack_score": 0.4
        }

        composite_score = sum(
            scores[metric] * weights[metric]
            for metric in weights.keys()
            if metric in scores
        )

        scores["composite_threat_score"] = min(1.0, composite_score)
        scores["calculation_timestamp"] = datetime.now().isoformat()

        return scores

    def get_threat_score(self) -> float:
        """Get the current composite threat score (0.0 to 1.0)."""
        return self.calculate_composite_threat_score()["composite_threat_score"]

    def collect_usage_stats(self) -> Dict:
        """Aggregate current metrics including threat scores."""
        # Get existing usage stats
        stats = self._collect_basic_usage_stats()

        # Add threat intelligence
        threat_scores = self.calculate_composite_threat_score()
        stats["threat_intelligence"] = threat_scores
        stats["composite_threat_score"] = threat_scores["composite_threat_score"]

        return stats

    def _collect_basic_usage_stats(self) -> Dict:
        """Aggregate basic usage metrics (original functionality)."""
        # Simulate collection (in real: query Prometheus or DB)
        handshake_counts = defaultdict(int)
        key_ops = defaultdict(int)

        # Gather from existing counters (simulated)
        # In practice, integrate with Prometheus API or persistent storage
        tenant_usage = {}

        for tenant in ['tenant_1', 'tenant_2', 'default']:  # Mock tenants
            tenant_usage[tenant] = {
                'handshakes_total': handshake_counts[tenant],
                'key_rotations': key_ops.get('rotate', 0),
                'algorithm_adoption': {
                    'kyber768': 60,  # percentage
                    'ml-kem-1024': 40,
                },
                'failover_events': 2,
            }

        return {
            'collection_timestamp': time.time(),
            'uptime_seconds': time.time() - self.start_time,
            'tenant_usage': tenant_usage,
            'global_stats': {
                'total_tenants': len(tenant_usage),
                'total_handshakes': sum(u['handshakes_total'] for u in tenant_usage.values()),
                'total_key_rotations': sum(u['key_rotations'] for u in tenant_usage.values()),
            }
        }

    def export_summary(self, filepath: str = "reports/lts_usage_summary.json"):
        """Export metrics to JSON."""
        data = self.collect_usage_stats()
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"Exported LTS metrics summary to {filepath}")
        return filepath

    def export_threat_report(self, filepath: str = "reports/threat_intelligence_report.json"):
        """Export comprehensive threat intelligence report."""
        report = {
            "report_timestamp": datetime.now().isoformat(),
            "threat_feeds_loaded": list(self.load_threat_feeds().keys()),
            "threat_scores": self.calculate_composite_threat_score(),
            "recommendations": self.generate_threat_recommendations()
        }

        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"Exported threat intelligence report to {filepath}")
        return filepath

    def generate_threat_recommendations(self) -> List[str]:
        """Generate actionable recommendations based on current threat landscape."""
        threat_scores = self.calculate_composite_threat_score()
        recommendations = []

        composite_score = threat_scores["composite_threat_score"]

        if composite_score >= 0.8:
            recommendations.extend([
                "URGENT: Implement immediate algorithm rotation to maximum security variants",
                "Enable enhanced monitoring for all cryptographic operations",
                "Consider emergency failover to offline backup systems",
                "Increase security alerting sensitivity"
            ])
        elif composite_score >= 0.6:
            recommendations.extend([
                "HIGH PRIORITY: Rotate to at least Level 3 security algorithms",
                "Enable additional threat detection monitoring",
                "Review and strengthen network perimeter defenses",
                "Increase key rotation frequency"
            ])
        elif composite_score >= 0.4:
            recommendations.extend([
                "MODERATE: Consider algorithm upgrades for sensitive communications",
                "Monitor system performance for cryptographic operations",
                "Review hardware security posture",
                "Update threat intelligence feeds"
            ])
        else:
            recommendations.extend([
                "LOW: Maintain current security posture with regular monitoring",
                "Schedule routine security assessments",
                "Keep systems updated with latest patches"
            ])

        return recommendations
