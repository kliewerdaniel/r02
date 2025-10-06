#!/usr/bin/env python3
"""
QASP AI Threat Monitor

Polls threat intelligence feeds and provides algorithm rotation recommendations
using a lightweight LLM policy engine.
"""

import json
import time
import requests
from pathlib import Path
from typing import List, Dict

class ThreatFeed:
    def __init__(self, feed_url_or_path: str):
        self.source = feed_url_or_path

    def poll(self) -> Dict:
        # Mock: Assume JSON feed of PQC risks and incidents
        if self.source.startswith('http'):
            return requests.get(self.source).json()
        else:
            with open(self.source, 'r') as f:
                return json.load(f)

class SemanticAdvisor:
    def __init__(self):
        self.knowledge_base = {
            'Kyber768': 'Standard choice, moderate risk',
            'ML-KEM-1024': 'Higher security, recommended on latitude issues',
            'Dilithium': 'Signature, low risk currently',
            'Lambdacypher': 'Post-quantum, experimental'
        }

    def recommend_rotation(self, threats: List[Dict]) -> str:
        # Simple heuristic (mock LLM)
        high_risks = [t for t in threats if t.get('risk_level') == 'high']
        if high_risks:
            return "Rotate to ML-KEM-1024: detected high-risk PQC weaknesses"
        if any('latency' in t.get('issue', '').lower() for t in threats):
            return "Suggest Lambdacypher for performance-critical paths"
        return "No rotation needed; current algorithms sufficient"

class AIThreatMonitor:
    def __init__(self, feeds: List[ThreatFeed], interval: int = 3600):
        self.feeds = feeds
        self.interval = interval
        self.advisor = SemanticAdvisor()
        self.threat_log = []

    def monitor_loop(self):
        while True:
            all_threats = []
            for feed in self.feeds:
                try:
                    data = feed.poll()
                    all_threats.extend(data.get('threats', []))
                except Exception as e:
                    print(f"Error polling {feed.source}: {e}")

            if all_threats:
                recommendation = self.advisor.recommend_rotation(all_threats)
                self.threat_log.append({
                    'timestamp': time.time(),
                    'threats': all_threats,
                    'recommendation': recommendation
                })
                print(f"AI Monitor: {recommendation}")
                # Log to file or send alert
                with open('src/ai_threat/recommendations.log', 'a') as f:
                    f.write(json.dumps(self.threat_log[-1], indent=2) + '\n')

            time.sleep(self.interval)

def main():
    # Example feeds: mock paths
    feeds = [
        ThreatFeed('threat_feeds/nist_pqc_risks.json'),
        ThreatFeed('threat_feeds/hardware_incidents.json')
    ]
    monitor = AIThreatMonitor(feeds, interval=3600)  # 1 hour
    monitor.monitor_loop()

if __name__ == '__main__':
    main()
