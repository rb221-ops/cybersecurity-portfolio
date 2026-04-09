#!/usr/bin/env python3
"""
Threat Intelligence Dashboard
Real-time security threat monitoring and visualization
Author: Riley (rb221-ops)
"""

import json
import random
from datetime import datetime, timedelta
from typing import List, Dict, Tuple
from collections import defaultdict
import argparse
from dataclasses import dataclass, asdict

@dataclass
class ThreatIndicator:
    """Data class for threat indicators"""
    indicator_type: str
    value: str
    severity: str
    source: str
    timestamp: str
    confidence: float
    description: str

class ThreatIntelligenceDashboard:
    """Real-time threat intelligence aggregation and analysis system"""
    
    def __init__(self):
        self.threats = []
        self.statistics = defaultdict(int)
        self.attack_patterns = []
        self.ioc_database = self.load_ioc_database()
        self.threat_feeds = []
        self.alerts = []
    
    def load_ioc_database(self) -> Dict:
        """Load Indicators of Compromise database"""
        return {
            'malware_hashes': [
                'd131dd02c5e6eee1f8b9e0d1dc52c0a5',
                '8f14e45fceea167a5a36dedd4bea2543',
                'c4ca4238a0b923820dcc509a6f75849b',
            ],
            'c2_domains': [
                'malicious.example.com',
                'payload-delivery.biz',
                'command-and-control.net',
                'botnet-c2.ru',
            ],
            'c2_ips': [
                '203.0.113.45',
                '198.51.100.89',
                '192.0.2.123',
                '198.51.100.220',
            ],
            'exploit_signatures': [
                'EternalBlue',
                'Wannacry',
                'Petya',
                'NotPetya',
                'CVE-2017-0144',
                'CVE-2019-0708',
            ]
        }
    
    def ingest_security_logs(self, logs: List[Dict]) -> List[Dict]:
        """Ingest and analyze security logs for threats"""
        print("[*] Ingesting security logs for threat analysis...")
        detected_threats = []
        
        for log_entry in logs:
            threat = self.analyze_log_for_threats(log_entry)
            if threat:
                detected_threats.append(threat)
                self.threats.append(threat)
        
        print(f"[+] Detected {len(detected_threats)} threats in logs")
        return detected_threats
    
    def analyze_log_for_threats(self, log_entry: Dict) -> Dict or None:
        """Analyze individual log entry for threat indicators"""
        
        # Check for known malware hashes
        if log_entry.get('file_hash') in self.ioc_database['malware_hashes']:
            return {
                'threat_id': f"TH-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                'type': 'Malware Detection',
                'severity': 'Critical',
                'indicator': log_entry['file_hash'],
                'description': f"Known malware hash detected: {log_entry['file_hash']}",
                'timestamp': datetime.now().isoformat(),
                'source': 'File Integrity Monitoring',
                'confidence': 0.99,
                'affected_host': log_entry.get('hostname'),
                'recommended_action': 'Isolate host immediately'
            }
        
        # Check for C2 domain communications
        if log_entry.get('destination_domain') in self.ioc_database['c2_domains']:
            return {
                'threat_id': f"TH-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                'type': 'C2 Communication',
                'severity': 'Critical',
                'indicator': log_entry['destination_domain'],
                'description': f"Known C2 domain detected: {log_entry['destination_domain']}",
                'timestamp': datetime.now().isoformat(),
                'source': 'Network Traffic Analysis',
                'confidence': 0.95,
                'source_ip': log_entry.get('source_ip'),
                'destination_ip': log_entry.get('destination_ip'),
                'recommended_action': 'Block domain, quarantine host'
            }
        
        # Check for C2 IP communications
        if log_entry.get('destination_ip') in self.ioc_database['c2_ips']:
            return {
                'threat_id': f"TH-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                'type': 'Suspicious Network Activity',
                'severity': 'Critical',
                'indicator': log_entry['destination_ip'],
                'description': f"Known malicious IP detected: {log_entry['destination_ip']}",
                'timestamp': datetime.now().isoformat(),
                'source': 'Network IDS',
                'confidence': 0.93,
                'source_host': log_entry.get('source_ip'),
                'protocol': log_entry.get('protocol'),
                'recommended_action': 'Block IP at firewall'
            }
        
        # Check for brute force attacks
        if log_entry.get('event_type') == 'authentication_failure':
            if log_entry.get('failure_count', 0) > 10:
                return {
                    'threat_id': f"TH-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                    'type': 'Brute Force Attack',
                    'severity': 'High',
                    'indicator': log_entry['source_ip'],
                    'description': f"Brute force attack detected from {log_entry['source_ip']}",
                    'timestamp': datetime.now().isoformat(),
                    'source': 'Authentication Logs',
                    'confidence': 0.85,
                    'target_user': log_entry.get('username'),
                    'attempt_count': log_entry['failure_count'],
                    'recommended_action': 'Block IP, enable account lockout'
                }
        
        # Check for data exfiltration patterns
        if log_entry.get('event_type') == 'data_transfer':
            if log_entry.get('data_volume', 0) > 500000000:  # 500MB threshold
                return {
                    'threat_id': f"TH-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                    'type': 'Potential Data Exfiltration',
                    'severity': 'High',
                    'indicator': f"{log_entry['source_ip']} -> {log_entry['destination_ip']}",
                    'description': f"Unusual volume of data transfer: {log_entry['data_volume']} bytes",
                    'timestamp': datetime.now().isoformat(),
                    'source': 'DLP System',
                    'confidence': 0.75,
                    'source_ip': log_entry['source_ip'],
                    'destination': log_entry.get('destination_ip'),
                    'recommended_action': 'Investigate user activity'
                }
        
        return None
    
    def aggregate_threat_feeds(self) -> List[Dict]:
        """Aggregate threat intelligence from multiple feeds"""
        print("[*] Aggregating threat intelligence feeds...")
        
        feeds = {
            'MISP Feed': [
                {'ioc': 'malicious_hash_1', 'type': 'file_hash', 'severity': 'High'},
                {'ioc': 'c2-server.ru', 'type': 'domain', 'severity': 'Critical'},
            ],
            'AlienVault OTX': [
                {'ioc': '198.51.100.99', 'type': 'ip', 'severity': 'High'},
                {'ioc': 'botnet-controller.biz', 'type': 'domain', 'severity': 'Critical'},
            ],
            'Abuse.ch': [
                {'ioc': 'hash123456', 'type': 'file_hash', 'severity': 'Critical'},
                {'ioc': '203.0.113.88', 'type': 'ip', 'severity': 'High'},
            ],
            'Team Cymru': [
                {'ioc': 'exploit-kit.net', 'type': 'domain', 'severity': 'High'},
                {'ioc': '192.0.2.222', 'type': 'ip', 'severity': 'Medium'},
            ]
        }
        
        aggregated = []
        for feed_name, indicators in feeds.items():
            for indicator in indicators:
                aggregated.append({
                    'feed': feed_name,
                    'timestamp': datetime.now().isoformat(),
                    **indicator
                })
        
        self.threat_feeds = aggregated
        print(f"[+] Aggregated {len(aggregated)} indicators from {len(feeds)} feeds")
        return aggregated
    
    def correlate_threats(self) -> List[Dict]:
        """Correlate threats across multiple data sources"""
        print("[*] Performing threat correlation analysis...")
        
        correlations = []
        
        # Check for attack patterns
        if len(self.threats) > 0:
            # Check for multi-stage attacks
            brute_force_threats = [t for t in self.threats if 'Brute Force' in t.get('type', '')]
            c2_threats = [t for t in self.threats if 'C2' in t.get('type', '')]
            
            if brute_force_threats and c2_threats:
                correlations.append({
                    'correlation_id': f"CORR-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                    'type': 'Multi-stage Attack Pattern',
                    'severity': 'Critical',
                    'description': 'Detected brute force attack followed by C2 communication',
                    'threats_involved': [t['threat_id'] for t in brute_force_threats + c2_threats],
                    'timestamp': datetime.now().isoformat(),
                    'attack_chain': [
                        'Initial Access (Brute Force)',
                        'Command & Control',
                        'Potential Data Exfiltration'
                    ],
                    'tactic': 'Lateral Movement',
                    'mitre_technique': 'T1021'
                })
        
        # Check for distributed attacks
        source_ips = defaultdict(list)
        for threat in self.threats:
            source = threat.get('source_ip') or threat.get('source_host')
            if source:
                source_ips[source].append(threat)
        
        for source, threats_from_source in source_ips.items():
            if len(threats_from_source) > 2:
                correlations.append({
                    'correlation_id': f"CORR-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                    'type': 'Distributed Attack',
                    'severity': 'High',
                    'description': f'Multiple threats from single source: {source}',
                    'source': source,
                    'threat_count': len(threats_from_source),
                    'timestamp': datetime.now().isoformat(),
                    'recommended_action': 'Investigate and block source'
                })
        
        print(f"[+] Found {len(correlations)} threat correlations")
        return correlations
    
    def generate_risk_score(self) -> Dict:
        """Generate overall security risk score"""
        print("[*] Calculating overall risk score...")
        
        if not self.threats:
            return {
                'overall_risk_score': 1.0,
                'risk_level': 'LOW',
                'timestamp': datetime.now().isoformat()
            }
        
        # Count threats by severity
        severity_weights = {
            'Critical': 40,
            'High': 25,
            'Medium': 10,
            'Low': 5
        }
        
        total_score = 0
        threat_breakdown = defaultdict(int)
        
        for threat in self.threats:
            severity = threat.get('severity', 'Low')
            threat_breakdown[severity] += 1
            confidence = threat.get('confidence', 0.5)
            total_score += severity_weights.get(severity, 0) * confidence
        
        # Normalize to 0-100 scale
        risk_score = min(100, (total_score / len(self.threats)) if self.threats else 0)
        
        if risk_score >= 75:
            risk_level = 'CRITICAL'
        elif risk_score >= 50:
            risk_level = 'HIGH'
        elif risk_score >= 25:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        return {
            'overall_risk_score': round(risk_score, 2),
            'risk_level': risk_level,
            'threats_detected': len(self.threats),
            'threat_breakdown': dict(threat_breakdown),
            'timestamp': datetime.now().isoformat(),
            'recommendations': self.get_risk_recommendations(risk_level)
        }
    
    def get_risk_recommendations(self, risk_level: str) -> List[str]:
        """Generate recommendations based on risk level"""
        if risk_level == 'CRITICAL':
            return [
                'IMMEDIATE: Activate incident response team',
                'Isolate affected systems immediately',
                'Enable enhanced monitoring and alerting',
                'Review all access logs for the past 24 hours',
                'Prepare for potential data breach notification'
            ]
        elif risk_level == 'HIGH':
            return [
                'Alert security team for investigation',
                'Increase monitoring of suspicious activities',
                'Review and tighten access controls',
                'Patch all critical vulnerabilities',
                'Conduct threat assessment'
            ]
        elif risk_level == 'MEDIUM':
            return [
                'Monitor for suspicious activity escalation',
                'Schedule vulnerability assessment',
                'Review security policies',
                'Plan security improvements'
            ]
        else:
            return [
                'Continue routine security monitoring',
                'Maintain current security posture',
                'Schedule regular security reviews'
            ]
    
    def generate_dashboard_report(self) -> Dict:
        """Generate comprehensive dashboard report"""
        print("[*] Generating threat intelligence dashboard report...")
        
        threats_by_type = defaultdict(int)
        threats_by_severity = defaultdict(int)
        top_sources = defaultdict(int)
        
        for threat in self.threats:
            threats_by_type[threat.get('type', 'Unknown')] += 1
            threats_by_severity[threat.get('severity', 'Unknown')] += 1
            source = threat.get('source_ip') or threat.get('source_host') or 'Unknown'
            top_sources[source] += 1
        
        correlations = self.correlate_threats()
        risk_score = self.generate_risk_score()
        threat_feeds = self.aggregate_threat_feeds()
        
        dashboard = {
            'report_timestamp': datetime.now().isoformat(),
            'summary': {
                'total_threats': len(self.threats),
                'total_correlations': len(correlations),
                'iocs_in_system': len(self.threat_feeds),
                'overall_risk_score': risk_score
            },
            'threat_statistics': {
                'by_type': dict(threats_by_type),
                'by_severity': dict(threats_by_severity),
                'top_threat_sources': dict(sorted(top_sources.items(), key=lambda x: x[1], reverse=True)[:5])
            },
            'recent_threats': self.threats[-10:],
            'threat_correlations': correlations,
            'threat_intelligence_feeds': threat_feeds[:10],
            'iocs_in_database': {
                'malware_hashes': len(self.ioc_database['malware_hashes']),
                'c2_domains': len(self.ioc_database['c2_domains']),
                'c2_ips': len(self.ioc_database['c2_ips']),
            },
            'recommendations': risk_score['recommendations'],
            'next_update': (datetime.now() + timedelta(minutes=5)).isoformat()
        }
        
        return dashboard
    
    def print_dashboard(self, dashboard: Dict):
        """Print formatted dashboard to console"""
        print("\n" + "="*80)
        print("THREAT INTELLIGENCE DASHBOARD")
        print("="*80)
        
        summary = dashboard['summary']
        print(f"\n[SUMMARY]")
        print(f"  Total Threats Detected: {summary['total_threats']}")
        print(f"  Threat Correlations: {summary['total_correlations']}")
        print(f"  Threat Intelligence: {summary['iocs_in_system']} IOCs")
        print(f"  Risk Score: {summary['overall_risk_score']['overall_risk_score']}/100 ({summary['overall_risk_score']['risk_level']})")
        
        print(f"\n[THREATS BY TYPE]")
        for threat_type, count in dashboard['threat_statistics']['by_type'].items():
            print(f"  {threat_type}: {count}")
        
        print(f"\n[THREATS BY SEVERITY]")
        for severity, count in dashboard['threat_statistics']['by_severity'].items():
            print(f"  {severity}: {count}")
        
        print(f"\n[TOP THREAT SOURCES]")
        for source, count in dashboard['threat_statistics']['top_threat_sources'].items():
            print(f"  {source}: {count} threats")
        
        print(f"\n[RECENT THREATS]")
        for threat in dashboard['recent_threats'][:3]:
            print(f"  [{threat['threat_id']}] {threat['type']}: {threat['description']}")
        
        print(f"\n[RECOMMENDATIONS]")
        for rec in dashboard['recommendations']:
            print(f"  • {rec}")
        
        print("\n" + "="*80)
    
    def save_dashboard(self, dashboard: Dict, filename: str = 'threat_dashboard.json'):
        """Save dashboard report to file"""
        with open(filename, 'w') as f:
            json.dump(dashboard, f, indent=2, default=str)
        print(f"[+] Dashboard saved to {filename}")

def main():
    parser = argparse.ArgumentParser(description='Threat Intelligence Dashboard')
    parser.add_argument('-o', '--output', default='threat_dashboard.json', help='Output file')
    args = parser.parse_args()
    
    print("\n" + "="*80)
    print("THREAT INTELLIGENCE DASHBOARD v1.0")
    print("Real-Time Security Threat Monitoring & Analysis")
    print("="*80)
    
    # Sample security logs for testing
    sample_logs = [
        {
            'file_hash': 'd131dd02c5e6eee1f8b9e0d1dc52c0a5',
            'hostname': 'workstation-01',
            'timestamp': datetime.now().isoformat()
        },
        {
            'destination_domain': 'malicious.example.com',
            'source_ip': '192.168.1.100',
            'destination_ip': '198.51.100.45',
            'timestamp': datetime.now().isoformat()
        },
        {
            'event_type': 'authentication_failure',
            'source_ip': '203.0.113.45',
            'username': 'admin',
            'failure_count': 15,
            'timestamp': datetime.now().isoformat()
        },
    ]
    
    # Initialize dashboard
    dashboard = ThreatIntelligenceDashboard()
    
    # Ingest logs and generate report
    dashboard.ingest_security_logs(sample_logs)
    report = dashboard.generate_dashboard_report()
    
    # Display and save
    dashboard.print_dashboard(report)
    dashboard.save_dashboard(report, args.output)

if __name__ == '__main__':
    main()
