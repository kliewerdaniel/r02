#!/usr/bin/env python3
"""
Policy Timeline Visualization Tool for QASP v2.0

Generates time-series graphs showing algorithm rotations, policy decisions,
and threat scores over time from the autonomous security orchestration logs.

Usage:
    python tools/visualize_policy_graph.py [--output reports/policy_timeline.svg] [--days 7]
"""

import json
import argparse
import sys
from pathlib import Path
from datetime import datetime, timedelta
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from typing import List, Dict, Any, Optional


class PolicyTimelineVisualizer:
    """Generates visualizations of QASP v2.0 policy decisions and algorithm rotations."""

    def __init__(self, policy_file: str = "reports/policy_decisions.json"):
        self.policy_file = Path(policy_file)
        self.threat_report_file = Path("reports/threat_intelligence_report.json")
        self.daemon_stats_file = Path("reports/rotation_daemon_stats.json")

    def load_policy_decisions(self) -> List[Dict[str, Any]]:
        """Load policy decisions from JSON file."""
        if not self.policy_file.exists():
            print(f"Warning: Policy decisions file {self.policy_file} not found")
            return []

        try:
            with open(self.policy_file, 'r') as f:
                data = json.load(f)
                return data.get("decisions", [])
        except Exception as e:
            print(f"Error loading policy decisions: {e}")
            return []

    def load_threat_intelligence(self) -> Dict[str, Any]:
        """Load threat intelligence data."""
        if not self.threat_report_file.exists():
            return {"threat_scores": []}

        try:
            with open(self.threat_report_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading threat intelligence: {e}")
            return {"threat_scores": []}

    def load_daemon_stats(self) -> Dict[str, Any]:
        """Load daemon monitoring statistics."""
        if not self.daemon_stats_file.exists():
            return {"final_policy_state": {}}

        try:
            with open(self.daemon_stats_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading daemon stats: {e}")
            return {"final_policy_state": {}}

    def parse_timestamps(self, decisions: List[Dict[str, Any]]) -> List[datetime]:
        """Parse timestamps from policy decisions."""
        timestamps = []
        for decision in decisions:
            try:
                timestamp_str = decision.get("timestamp")
                if timestamp_str:
                    # Try different timestamp formats
                    try:
                        dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                    except ValueError:
                        dt = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%f%z")
                    timestamps.append(dt)
            except Exception:
                continue
        return timestamps

    def create_algorithm_timeline(self, decisions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create timeline data for algorithm states."""
        timeline = []
        current_kem = "Kyber512"  # Default
        current_sig = "Dilithium3"  # Default

        # Start with default state
        initial_time = datetime.now() - timedelta(days=7)
        timeline.append({
            'timestamp': initial_time,
            'kem': current_kem,
            'sig': current_sig,
            'action': 'initial'
        })

        for decision in decisions:
            try:
                timestamp_str = decision.get("timestamp")
                if timestamp_str:
                    try:
                        dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                    except ValueError:
                        dt = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%f%z")

                    new_algorithms = decision.get("new_algorithms", {})
                    if new_algorithms:
                        current_kem = new_algorithms.get("kem", current_kem)
                        current_sig = new_algorithms.get("sig", current_sig)

                    timeline.append({
                        'timestamp': dt,
                        'kem': current_kem,
                        'sig': current_sig,
                        'action': decision.get("action", "unknown"),
                        'confidence': decision.get("confidence", 0.0)
                    })
            except Exception:
                continue

        return {"timeline": timeline, "current_kem": current_kem, "current_sig": current_sig}

    def generate_svg_timeline(self, output_file: str = "reports/policy_timeline.svg",
                            days: int = 7) -> None:
        """Generate SVG timeline visualization."""
        # Load data
        decisions = self.load_policy_decisions()
        threat_data = self.load_threat_intelligence()

        if not decisions:
            print("No policy decisions found to visualize")
            return

        # Parse timestamps
        timestamps = self.parse_timestamps(decisions)
        if not timestamps:
            print("No valid timestamps found in policy decisions")
            return

        # Filter by date range
        cutoff_date = datetime.now() - timedelta(days=days)
        recent_decisions = [
            d for d, ts in zip(decisions, timestamps)
            if ts >= cutoff_date
        ]

        if not recent_decisions:
            print(f"No decisions found in last {days} days")
            return

        # Create figure with subplots
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 8), height_ratios=[2, 1])

        # Algorithm timeline subplot
        algorithm_data = self.create_algorithm_timeline(recent_decisions)

        # Plot algorithm changes
        kem_versions = []
        sig_versions = []
        change_times = []
        confidences = []

        for entry in algorithm_data["timeline"]:
            if entry['timestamp'] >= cutoff_date:
                change_times.append(entry['timestamp'])
                # Convert algorithm names to numeric values for plotting
                kem_val = self._algorithm_to_number(entry['kem'])
                sig_val = self._algorithm_to_number(entry['sig'])
                kem_versions.append(kem_val)
                sig_versions.append(sig_val)
                confidences.append(entry.get('confidence', 0.5))

        if change_times:
            # Plot KEM algorithms
            ax1.step(change_times, kem_versions, where='post', label='KEM Algorithm',
                    linewidth=2, color='#1f77b4', alpha=0.8)

            # Plot Signature algorithms
            ax2.step(change_times, sig_versions, where='post', label='Signature Algorithm',
                    linewidth=2, color='#ff7f0e', alpha=0.8)

            # Add confidence markers
            for i, (time, conf) in enumerate(zip(change_times[1:], confidences[1:])):  # Skip initial state
                if conf > 0.5:  # Only show high confidence points
                    ax1.scatter(time, kem_versions[i+1], c='red', s=50*conf, alpha=0.7,
                              marker='o', edgecolors='black')
                    ax2.scatter(time, sig_versions[i+1], c='red', s=50*conf, alpha=0.7,
                              marker='o', edgecolors='black')

        # Configure KEM subplot
        ax1.set_title('QASP v2.0 Algorithm Rotation Timeline', fontsize=14, fontweight='bold')
        ax1.set_ylabel('KEM Algorithm', fontsize=12)
        ax1.set_yticks(list(self._algorithm_numbers.keys()))
        ax1.set_yticklabels(list(self._algorithm_numbers.keys()))
        ax1.grid(True, alpha=0.3)
        ax1.legend()

        # Configure Signature subplot
        ax2.set_ylabel('Signature Algorithm', fontsize=12)
        ax2.set_yticks(list(self._algorithm_numbers.keys()))
        ax2.set_yticklabels(list(self._algorithm_numbers.keys()))
        ax2.grid(True, alpha=0.3)
        ax2.legend()

        # Format x-axis dates
        for ax in [ax1, ax2]:
            ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d %H:%M'))
            ax.xaxis.set_minor_formatter(mdates.DateFormatter('%H:%M'))
            plt.setp(ax.xaxis.get_majorticklabels(), rotation=45, ha='right')

        # Set x-axis limits
        if change_times:
            ax1.set_xlim(cutoff_date, datetime.now())
            ax2.set_xlim(cutoff_date, datetime.now())

        plt.tight_layout()
        plt.savefig(output_file, format='svg', dpi=300, bbox_inches='tight')
        plt.close()

        print(f"Policy timeline visualization saved to {output_file}")

        # Print summary statistics
        self._print_summary_stats(recent_decisions, days)

    def _algorithm_to_number(self, algorithm: str) -> int:
        """Convert algorithm name to numeric value for plotting."""
        if not hasattr(self, '_algorithm_numbers'):
            self._algorithm_numbers = {
                "Kyber512": 1,
                "Kyber768": 2,
                "Kyber1024": 3,
                "FrodoKEM-640-AES": 4,
                "Dilithium2": 1,
                "Dilithium3": 2,
                "Dilithium5": 3,
                "Falcon-512": 4
            }

        return self._algorithm_numbers.get(algorithm, 0)

    def _print_summary_stats(self, decisions: List[Dict[str, Any]], days: int):
        """Print summary statistics of policy decisions."""
        if not decisions:
            return

        stats = {
            "total_decisions": len(decisions),
            "rotations": sum(1 for d in decisions if d.get("action") == "rotate"),
            "rollbacks": sum(1 for d in decisions if d.get("action") == "rollback"),
            "maintains": sum(1 for d in decisions if d.get("action") == "maintain"),
            "avg_confidence": sum(d.get("confidence", 0) for d in decisions) / len(decisions)
        }

        print("\n--- Policy Timeline Summary ---")
        print(f"Time Period: Last {days} days")
        print(f"Total Decisions: {stats['total_decisions']}")
        print(f"Rotations: {stats['rotations']}")
        print(f"Rollbacks: {stats['rollbacks']}")
        print(f"Maintenance Actions: {stats['maintains']}")
        print(".2f"        print("Algorithm Transitions:")

        algorithm_changes = []
        for decision in decisions:
            if decision.get("action") == "rotate":
                new_alg = decision.get("new_algorithms", {})
                prev_alg = decision.get("prev_algorithms", {})
                if new_alg:
                    kem_change = f"{prev_alg.get('kem', 'unknown')} → {new_alg.get('kem', 'unknown')}"
                    sig_change = f"{prev_alg.get('sig', 'unknown')} → {new_alg.get('sig', 'unknown')}"
                    algorithm_changes.append(f"KEM: {kem_change}, SIG: {sig_change}")

        for i, change in enumerate(algorithm_changes[:5]):  # Show first 5
            print(f"  {i+1}. {change}")

        if len(algorithm_changes) > 5:
            print(f"  ... and {len(algorithm_changes) - 5} more")


def main():
    """Main entry point for the visualization tool."""
    parser = argparse.ArgumentParser(
        description="Generate QASP v2.0 policy decision timeline visualizations"
    )
    parser.add_argument(
        "--output", "-o",
        default="reports/policy_timeline.svg",
        help="Output file path for the SVG visualization"
    )
    parser.add_argument(
        "--days", "-d",
        type=int,
        default=7,
        help="Number of days to include in the timeline (default: 7)"
    )
    parser.add_argument(
        "--policy-file",
        default="reports/policy_decisions.json",
        help="Path to policy decisions JSON file"
    )

    args = parser.parse_args()

    # Create output directory if it doesn't exist
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)

    # Generate visualization
    visualizer = PolicyTimelineVisualizer(policy_file=args.policy_file)
    visualizer.generate_svg_timeline(
        output_file=args.output,
        days=args.days
    )


if __name__ == "__main__":
    main()
