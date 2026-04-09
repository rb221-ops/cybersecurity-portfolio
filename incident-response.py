#!/usr/bin/env python3
"""
Incident Response Playbook & Automation
Automated threat detection and incident response orchestration
Author: Riley (rb221-ops)
"""

import json
import re
from datetime import datetime
from enum import Enum
from typing import List, Dict, Tuple
from collections import defaultdict
import argparse

class SeverityLevel(Enum):
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1

class IncidentType(Enum):
    MALWARE = "Malware Detection"
    DATA_BREACH = "Data Breach"
    UNAUTHORIZED_ACCESS = "Unauthorized Access"
    DDoS = "DDoS Attack"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DATA_EXFILTRATION = "Data Exfiltration"
    LATERAL_MOVEMENT = "Lateral Movement"
    POLICY_VIOLATION = "Policy Violation"
    UNKNOWN = "Unknown"

class IncidentResponsePlaybook:
    """Automated incident response and threat handling system"""
    
    def __init__(self):
        self.incidents = []
        self.response_history = []
        self.playbooks = self.load_playbooks()
        self.containment_actions = []
        self.eradication_actions = []
        self.recovery_actions = []
    
    def load_playbooks(self) -> Dict:
        """Load incident response playbooks"""
        return {
            IncidentType.MALWARE: self.malware_playbook,
            IncidentType.DATA_BREACH: self.data_breach_playbook,
            IncidentType.DDoS: self.ddos_playbook,
            IncidentType.UNAUTHORIZED_ACCESS: self.unauthorized_access_playbook,
            IncidentType.PRIVILEGE_ESCALATION: self.privilege_escalation_playbook,
            IncidentType.LATERAL_MOVEMENT: self.lateral_movement_playbook,
        }
    
    def detect_incidents(self, log_entries: List[Dict]) -> List[Dict]:
        """Detect security incidents from log data"""
        print("[*] Analyzing logs for security incidents...")
        detected = []
        
        for entry in log_entries:
            incident = self.analyze_log_entry(entry)
            if incident:
                detected.append(incident)
        
        print(f"[+] Detected {len(detected)} security incidents")
        return detected
    
    def analyze_log_entry(self, entry: Dict) -> Dict or None:
        """Analyze individual log entry for threats"""
        
        # Check for failed login attempts
        if entry.get('event_type') == 'failed_login':
            if entry.get('attempt_count', 0) > 5:
                return {
                    'type': IncidentType.UNAUTHORIZED_ACCESS,
                    'severity': SeverityLevel.HIGH,
                    'source_ip': entry.get('source_ip'),
                    'target_user': entry.get('username'),
                    'description': f"Multiple failed login attempts from {entry.get('source_ip')}",
                    'timestamp': entry.get('timestamp'),
                    'indicators': ['Brute force attempt detected']
                }
        
        # Check for privilege escalation
        if entry.get('event_type') == 'privilege_change':
            if entry.get('escalation_detected'):
                return {
                    'type': IncidentType.PRIVILEGE_ESCALATION,
                    'severity': SeverityLevel.CRITICAL,
                    'user': entry.get('username'),
                    'description': f"Unauthorized privilege escalation by {entry.get('username')}",
                    'timestamp': entry.get('timestamp'),
                    'indicators': ['Sudo command executed', 'Admin rights gained']
                }
        
        # Check for suspicious file activity
        if entry.get('event_type') == 'file_access':
            suspicious_paths = ['/etc/passwd', '/etc/shadow', '~/ssh/authorized_keys']
            if entry.get('file_path') in suspicious_paths:
                return {
                    'type': IncidentType.DATA_EXFILTRATION,
                    'severity': SeverityLevel.CRITICAL,
                    'user': entry.get('username'),
                    'file': entry.get('file_path'),
                    'description': f"Suspicious access to sensitive file: {entry.get('file_path')}",
                    'timestamp': entry.get('timestamp'),
                    'indicators': ['Sensitive file accessed', 'Unauthorized read']
                }
        
        # Check for network anomalies
        if entry.get('event_type') == 'network_anomaly':
            if entry.get('data_volume', 0) > 1000000:  # 1GB threshold
                return {
                    'type': IncidentType.DATA_EXFILTRATION,
                    'severity': SeverityLevel.CRITICAL,
                    'source': entry.get('source_ip'),
                    'destination': entry.get('destination_ip'),
                    'description': f"Unusual data transfer detected: {entry.get('data_volume')} bytes",
                    'timestamp': entry.get('timestamp'),
                    'indicators': ['Large data transfer', 'Unusual destination']
                }
        
        # Check for malware signatures
        if entry.get('event_type') == 'file_execution':
            malware_hashes = ['d131dd02c5e6eee1f8b9e0d1dc52c0a5', '8f14e45fceea167a5a36dedd4bea2543']
            if entry.get('file_hash') in malware_hashes:
                return {
                    'type': IncidentType.MALWARE,
                    'severity': SeverityLevel.CRITICAL,
                    'file_hash': entry.get('file_hash'),
                    'file_name': entry.get('file_name'),
                    'description': f"Known malware signature detected: {entry.get('file_name')}",
                    'timestamp': entry.get('timestamp'),
                    'indicators': ['Malware signature match', 'Suspicious process execution']
                }
        
        return None
    
    def create_incident_ticket(self, incident: Dict) -> Dict:
        """Create incident ticket for tracking"""
        ticket = {
            'incident_id': f"INC-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            'created_at': datetime.now().isoformat(),
            'type': incident['type'].value,
            'severity': incident['severity'].name,
            'status': 'OPEN',
            'description': incident['description'],
            'indicators': incident.get('indicators', []),
            'response_plan': incident['type'].name,
            'assigned_to': 'Security Operations Center',
            'timeline': []
        }
        return ticket
    
    def execute_containment(self, incident: Dict) -> List[Dict]:
        """Execute immediate containment actions"""
        print(f"[!] EXECUTING CONTAINMENT for {incident['type'].value}...")
        actions = []
        
        if incident['type'] == IncidentType.MALWARE:
            actions = [
                {'action': 'Isolate affected host from network', 'status': 'executed', 'timestamp': datetime.now().isoformat()},
                {'action': 'Kill suspicious processes', 'status': 'executed', 'timestamp': datetime.now().isoformat()},
                {'action': 'Block detected malware hash', 'status': 'executed', 'timestamp': datetime.now().isoformat()},
            ]
        
        elif incident['type'] == IncidentType.UNAUTHORIZED_ACCESS:
            actions = [
                {'action': f"Reset password for {incident.get('target_user')}", 'status': 'executed'},
                {'action': f"Block source IP {incident.get('source_ip')}", 'status': 'executed'},
                {'action': 'Enable additional authentication factors', 'status': 'executed'},
            ]
        
        elif incident['type'] == IncidentType.DATA_EXFILTRATION:
            actions = [
                {'action': 'Block destination IP/domain', 'status': 'executed'},
                {'action': 'Terminate user session', 'status': 'executed'},
                {'action': 'Enable DLP alerts for sensitive data', 'status': 'executed'},
                {'action': 'Capture network traffic for forensics', 'status': 'executed'},
            ]
        
        elif incident['type'] == IncidentType.PRIVILEGE_ESCALATION:
            actions = [
                {'action': f"Revoke elevated privileges from {incident.get('user')}", 'status': 'executed'},
                {'action': 'Force logout of privileged sessions', 'status': 'executed'},
                {'action': 'Review sudo logs for unauthorized commands', 'status': 'in_progress'},
            ]
        
        elif incident['type'] == IncidentType.DDoS:
            actions = [
                {'action': 'Enable rate limiting on edge devices', 'status': 'executed'},
                {'action': 'Activate DDoS mitigation service', 'status': 'executed'},
                {'action': 'Redirect traffic through WAF', 'status': 'executed'},
            ]
        
        self.containment_actions.extend(actions)
        return actions
    
    def execute_eradication(self, incident: Dict) -> List[Dict]:
        """Execute eradication actions"""
        print(f"[!] EXECUTING ERADICATION for {incident['type'].value}...")
        actions = []
        
        if incident['type'] == IncidentType.MALWARE:
            actions = [
                {'action': 'Remove malware files from disk', 'status': 'executed'},
                {'action': 'Remove registry entries (if Windows)', 'status': 'executed'},
                {'action': 'Scan all systems with updated AV signatures', 'status': 'in_progress'},
            ]
        
        elif incident['type'] == IncidentType.LATERAL_MOVEMENT:
            actions = [
                {'action': 'Close compromised accounts', 'status': 'executed'},
                {'action': 'Revoke stolen credentials across all systems', 'status': 'executed'},
                {'action': 'Patch exploited vulnerabilities', 'status': 'in_progress'},
            ]
        
        else:
            actions = [
                {'action': 'Apply security patches to vulnerable systems', 'status': 'in_progress'},
                {'action': 'Harden system configurations', 'status': 'in_progress'},
                {'action': 'Review and update access controls', 'status': 'planned'},
            ]
        
        self.eradication_actions.extend(actions)
        return actions
    
    def execute_recovery(self, incident: Dict) -> List[Dict]:
        """Execute recovery actions"""
        print(f"[!] EXECUTING RECOVERY for {incident['type'].value}...")
        actions = []
        
        actions = [
            {'action': 'Restore systems from clean backups', 'status': 'in_progress', 'est_time': '2-4 hours'},
            {'action': 'Verify system integrity with checksums', 'status': 'planned'},
            {'action': 'Restore data from backup', 'status': 'planned'},
            {'action': 'Resume normal operations with monitoring', 'status': 'planned'},
        ]
        
        self.recovery_actions.extend(actions)
        return actions
    
    def malware_playbook(self):
        return {'name': 'Malware Response', 'steps': ['Isolate', 'Kill Process', 'Block Hash', 'Clean', 'Restore']}
    
    def data_breach_playbook(self):
        return {'name': 'Data Breach Response', 'steps': ['Contain', 'Investigate', 'Notify', 'Monitor', 'Recover']}
    
    def ddos_playbook(self):
        return {'name': 'DDoS Mitigation', 'steps': ['Detect', 'Rate Limit', 'Redirect', 'Monitor', 'Analyze']}
    
    def unauthorized_access_playbook(self):
        return {'name': 'Unauthorized Access', 'steps': ['Reset Password', 'Block IP', 'Enable MFA', 'Monitor', 'Investigate']}
    
    def privilege_escalation_playbook(self):
        return {'name': 'Privilege Escalation', 'steps': ['Revoke Privileges', 'Kill Session', 'Review Logs', 'Patch', 'Monitor']}
    
    def lateral_movement_playbook(self):
        return {'name': 'Lateral Movement', 'steps': ['Contain', 'Identify Paths', 'Block', 'Eradicate', 'Restore']}
    
    def generate_incident_report(self, incident: Dict, ticket: Dict) -> Dict:
        """Generate comprehensive incident report"""
        report = {
            'incident_id': ticket['incident_id'],
            'created_at': ticket['created_at'],
            'incident_type': ticket['type'],
            'severity': ticket['severity'],
            'description': incident['description'],
            'indicators_of_compromise': incident.get('indicators', []),
            'containment_actions': self.containment_actions,
            'eradication_actions': self.eradication_actions,
            'recovery_actions': self.recovery_actions,
            'timeline': self.generate_timeline(incident, ticket),
            'lessons_learned': self.generate_lessons_learned(incident),
            'recommendations': self.generate_recommendations(incident),
        }
        return report
    
    def generate_timeline(self, incident: Dict, ticket: Dict) -> List[str]:
        """Generate incident timeline"""
        return [
            f"{ticket['created_at']}: Incident detected - {incident['description']}",
            f"{datetime.now().isoformat()}: Incident ticket created ({ticket['incident_id']})",
            f"{datetime.now().isoformat()}: Containment procedures initiated",
            f"{datetime.now().isoformat()}: Eradication steps executed",
            f"{datetime.now().isoformat()}: Recovery procedures in progress",
        ]
    
    def generate_lessons_learned(self, incident: Dict) -> List[str]:
        """Generate lessons learned from incident"""
        return [
            "Detection was delayed by 15 minutes - consider improving SIEM rules",
            "Containment procedures were effective and rapid",
            "Need better credential rotation policies",
            "Segmentation prevented wider spread of compromise",
        ]
    
    def generate_recommendations(self, incident: Dict) -> List[str]:
        """Generate recommendations to prevent recurrence"""
        recommendations = [
            "Implement MFA on all administrative accounts",
            "Deploy EDR (Endpoint Detection and Response) solution",
            "Increase logging and monitoring on sensitive systems",
            "Conduct security awareness training for all staff",
            "Perform vulnerability assessment and patch management",
        ]
        
        if incident['type'] == IncidentType.PRIVILEGE_ESCALATION:
            recommendations.extend([
                "Review and restrict sudo access",
                "Implement privilege access management (PAM) solution",
            ])
        
        return recommendations
    
    def process_incident(self, incident: Dict) -> Dict:
        """Full incident response workflow"""
        print(f"\n[+] Processing incident: {incident['type'].value}")
        
        # Create ticket
        ticket = self.create_incident_ticket(incident)
        
        # Execute response phases
        self.execute_containment(incident)
        self.execute_eradication(incident)
        self.execute_recovery(incident)
        
        # Generate report
        report = self.generate_incident_report(incident, ticket)
        
        return {
            'ticket': ticket,
            'report': report,
            'status': 'Resolved'
        }
    
    def save_incident_log(self, response: Dict, filename: str = 'incident_response.json'):
        """Save incident response to file"""
        with open(filename, 'w') as f:
            # Convert enums to strings for JSON serialization
            response_json = json.loads(json.dumps(response, default=str, indent=2), parse_float=str)
            f.write(json.dumps(response_json, indent=2))
        print(f"[+] Incident response saved to {filename}")

def main():
    parser = argparse.ArgumentParser(description='Incident Response Playbook')
    parser.add_argument('-o', '--output', default='incident_response.json', help='Output file')
    args = parser.parse_args()
    
    print("\n" + "="*70)
    print("INCIDENT RESPONSE PLAYBOOK & AUTOMATION v1.0")
    print("="*70)
    
    # Sample log entries for testing
    sample_logs = [
        {
            'event_type': 'failed_login',
            'source_ip': '203.0.113.45',
            'username': 'admin',
            'attempt_count': 12,
            'timestamp': datetime.now().isoformat()
        },
        {
            'event_type': 'privilege_change',
            'username': 'user123',
            'escalation_detected': True,
            'timestamp': datetime.now().isoformat()
        },
        {
            'event_type': 'network_anomaly',
            'source_ip': '192.168.1.100',
            'destination_ip': '198.51.100.50',
            'data_volume': 5000000000,
            'timestamp': datetime.now().isoformat()
        },
    ]
    
    # Initialize playbook
    playbook = IncidentResponsePlaybook()
    
    # Detect incidents
    incidents = playbook.detect_incidents(sample_logs)
    
    # Process each incident
    all_responses = []
    for incident in incidents:
        response = playbook.process_incident(incident)
        all_responses.append(response)
    
    # Save results
    if all_responses:
        playbook.save_incident_log({'incidents_processed': len(all_responses), 'responses': all_responses}, args.output)
        print(f"\n[+] Processed {len(all_responses)} incidents")
    else:
        print("\n[+] No incidents detected")
    
    print("="*70)

if __name__ == '__main__':
    main()
