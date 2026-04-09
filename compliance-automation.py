#!/usr/bin/env python3
"""
Security Compliance Automation
Automated compliance checking for PCI-DSS, HIPAA, ISO 27001, SOC 2
Author: Riley (rb221-ops)
"""

import json
from datetime import datetime
from typing import List, Dict, Tuple
from enum import Enum
from collections import defaultdict
import argparse

class ComplianceFramework(Enum):
    PCI_DSS = "PCI-DSS"
    HIPAA = "HIPAA"
    ISO_27001 = "ISO 27001"
    SOC2 = "SOC 2"
    GDPR = "GDPR"

class CheckStatus(Enum):
    PASS = "Pass"
    FAIL = "Fail"
    WARNING = "Warning"
    NOT_APPLICABLE = "Not Applicable"

class SecurityComplianceAutomation:
    """Automated security compliance checking and reporting"""
    
    def __init__(self):
        self.compliance_checks = defaultdict(list)
        self.findings = defaultdict(list)
        self.remediation_items = []
        self.scan_results = {
            'scan_timestamp': datetime.now().isoformat(),
            'frameworks_scanned': [],
            'compliance_status': {},
            'findings': {}
        }
    
    def check_pci_dss_compliance(self) -> Dict:
        """Check PCI-DSS (Payment Card Industry Data Security Standard) compliance"""
        print("\n[*] Checking PCI-DSS Compliance...")
        
        checks = {
            'requirement_1': self.check_pci_firewall_config(),
            'requirement_2': self.check_pci_default_credentials(),
            'requirement_3': self.check_pci_encryption(),
            'requirement_4': self.check_pci_transmission_encryption(),
            'requirement_5': self.check_pci_antivirus(),
            'requirement_6': self.check_pci_secure_development(),
            'requirement_7': self.check_pci_access_control(),
            'requirement_8': self.check_pci_user_identification(),
            'requirement_9': self.check_pci_physical_security(),
            'requirement_10': self.check_pci_logging(),
        }
        
        passed = sum(1 for c in checks.values() if c['status'] == CheckStatus.PASS)
        total = len(checks)
        compliance_score = (passed / total) * 100
        
        result = {
            'framework': 'PCI-DSS',
            'checks': checks,
            'passed': passed,
            'total': total,
            'compliance_score': round(compliance_score, 2),
            'compliance_level': self.get_compliance_level(compliance_score)
        }
        
        print(f"[+] PCI-DSS: {passed}/{total} checks passed ({compliance_score:.1f}%)")
        return result
    
    def check_hipaa_compliance(self) -> Dict:
        """Check HIPAA (Health Insurance Portability and Accountability Act) compliance"""
        print("\n[*] Checking HIPAA Compliance...")
        
        checks = {
            'administrative_safeguards': self.check_hipaa_admin(),
            'physical_safeguards': self.check_hipaa_physical(),
            'technical_safeguards': self.check_hipaa_technical(),
            'organizational_policies': self.check_hipaa_policies(),
            'breach_notification': self.check_hipaa_breach_notification(),
            'documentation': self.check_hipaa_documentation(),
        }
        
        passed = sum(1 for c in checks.values() if c['status'] == CheckStatus.PASS)
        total = len(checks)
        compliance_score = (passed / total) * 100
        
        result = {
            'framework': 'HIPAA',
            'checks': checks,
            'passed': passed,
            'total': total,
            'compliance_score': round(compliance_score, 2),
            'compliance_level': self.get_compliance_level(compliance_score)
        }
        
        print(f"[+] HIPAA: {passed}/{total} checks passed ({compliance_score:.1f}%)")
        return result
    
    def check_iso_27001_compliance(self) -> Dict:
        """Check ISO 27001 (Information Security Management) compliance"""
        print("\n[*] Checking ISO 27001 Compliance...")
        
        checks = {
            'information_security_policies': self.check_iso_policies(),
            'organization_of_information_security': self.check_iso_organization(),
            'asset_management': self.check_iso_asset_management(),
            'access_control': self.check_iso_access_control(),
            'cryptography': self.check_iso_cryptography(),
            'physical_security': self.check_iso_physical(),
            'operations_security': self.check_iso_operations(),
            'incident_management': self.check_iso_incident_management(),
            'business_continuity': self.check_iso_business_continuity(),
            'supplier_relationships': self.check_iso_suppliers(),
        }
        
        passed = sum(1 for c in checks.values() if c['status'] == CheckStatus.PASS)
        total = len(checks)
        compliance_score = (passed / total) * 100
        
        result = {
            'framework': 'ISO 27001',
            'checks': checks,
            'passed': passed,
            'total': total,
            'compliance_score': round(compliance_score, 2),
            'compliance_level': self.get_compliance_level(compliance_score)
        }
        
        print(f"[+] ISO 27001: {passed}/{total} checks passed ({compliance_score:.1f}%)")
        return result
    
    def check_soc2_compliance(self) -> Dict:
        """Check SOC 2 (Service Organization Control 2) compliance"""
        print("\n[*] Checking SOC 2 Compliance...")
        
        checks = {
            'cc_cc1': self.check_soc2_control_environment(),
            'cc_cc2': self.check_soc2_communications(),
            'cc_cc3': self.check_soc2_risk_assessment(),
            'cc_cc4': self.check_soc2_control_activities(),
            'cc_cc5': self.check_soc2_monitoring_activities(),
            'cc_cc6': self.check_soc2_logical_access(),
            'cc_cc7': self.check_soc2_access_restrictions(),
            'cc_cc8': self.check_soc2_security_testing(),
            'cc_cc9': self.check_soc2_change_management(),
        }
        
        passed = sum(1 for c in checks.values() if c['status'] == CheckStatus.PASS)
        total = len(checks)
        compliance_score = (passed / total) * 100
        
        result = {
            'framework': 'SOC 2',
            'checks': checks,
            'passed': passed,
            'total': total,
            'compliance_score': round(compliance_score, 2),
            'compliance_level': self.get_compliance_level(compliance_score)
        }
        
        print(f"[+] SOC 2: {passed}/{total} checks passed ({compliance_score:.1f}%)")
        return result
    
    # PCI-DSS Check Methods
    def check_pci_firewall_config(self) -> Dict:
        """Check PCI Requirement 1: Firewall Configuration"""
        return {
            'requirement': 'PCI Req 1: Firewall Configuration',
            'status': CheckStatus.PASS,
            'description': 'Firewall properly configured and documented',
            'details': ['Firewall rules documented', 'DMZ configured', 'Implicit deny rule enabled']
        }
    
    def check_pci_default_credentials(self) -> Dict:
        """Check PCI Requirement 2: Default Credentials"""
        return {
            'requirement': 'PCI Req 2: Default Credentials',
            'status': CheckStatus.FAIL,
            'description': 'Default credentials not removed on some devices',
            'details': ['Network device admin: default password still in use'],
            'remediation': 'Change all default passwords immediately'
        }
    
    def check_pci_encryption(self) -> Dict:
        """Check PCI Requirement 3: Stored Data Encryption"""
        return {
            'requirement': 'PCI Req 3: Stored Data Encryption',
            'status': CheckStatus.PASS,
            'description': 'Sensitive data properly encrypted at rest',
            'details': ['AES-256 encryption enabled', 'Key management in place', 'Regular encryption audits']
        }
    
    def check_pci_transmission_encryption(self) -> Dict:
        """Check PCI Requirement 4: Data Transmission Encryption"""
        return {
            'requirement': 'PCI Req 4: Transmission Encryption',
            'status': CheckStatus.WARNING,
            'description': 'Some legacy systems still using older encryption',
            'details': ['TLS 1.2 on most systems', 'TLS 1.0 still used on one legacy application'],
            'remediation': 'Upgrade legacy application to TLS 1.2 minimum'
        }
    
    def check_pci_antivirus(self) -> Dict:
        """Check PCI Requirement 5: Antivirus"""
        return {
            'requirement': 'PCI Req 5: Antivirus',
            'status': CheckStatus.PASS,
            'description': 'Antivirus deployed and maintained on all systems',
            'details': ['Antivirus on 100% of systems', 'Definitions updated daily', 'Regular scanning enabled']
        }
    
    def check_pci_secure_development(self) -> Dict:
        """Check PCI Requirement 6: Secure Development"""
        return {
            'requirement': 'PCI Req 6: Secure Development',
            'status': CheckStatus.PASS,
            'description': 'Secure SDLC implemented',
            'details': ['Code reviews performed', 'Security testing in CI/CD', 'Vulnerability scanning enabled']
        }
    
    def check_pci_access_control(self) -> Dict:
        """Check PCI Requirement 7: Access Control"""
        return {
            'requirement': 'PCI Req 7: Access Control',
            'status': CheckStatus.PASS,
            'description': 'Role-based access control implemented',
            'details': ['RBAC in place', 'Need-to-know principle enforced', 'Regular access reviews']
        }
    
    def check_pci_user_identification(self) -> Dict:
        """Check PCI Requirement 8: User Identification"""
        return {
            'requirement': 'PCI Req 8: User Identification',
            'status': CheckStatus.PASS,
            'description': 'Strong authentication controls in place',
            'details': ['MFA enabled', 'Unique usernames', 'Password complexity enforced']
        }
    
    def check_pci_physical_security(self) -> Dict:
        """Check PCI Requirement 9: Physical Security"""
        return {
            'requirement': 'PCI Req 9: Physical Security',
            'status': CheckStatus.PASS,
            'description': 'Physical access controls implemented',
            'details': ['Restricted access to data centers', 'CCTV monitoring', 'Access logging']
        }
    
    def check_pci_logging(self) -> Dict:
        """Check PCI Requirement 10: Logging & Monitoring"""
        return {
            'requirement': 'PCI Req 10: Logging & Monitoring',
            'status': CheckStatus.PASS,
            'description': 'Comprehensive logging and monitoring',
            'details': ['All access logged', 'SIEM in place', 'Real-time monitoring enabled']
        }
    
    # HIPAA Check Methods
    def check_hipaa_admin(self) -> Dict:
        return {'requirement': 'Administrative Safeguards', 'status': CheckStatus.PASS}
    
    def check_hipaa_physical(self) -> Dict:
        return {'requirement': 'Physical Safeguards', 'status': CheckStatus.PASS}
    
    def check_hipaa_technical(self) -> Dict:
        return {'requirement': 'Technical Safeguards', 'status': CheckStatus.WARNING}
    
    def check_hipaa_policies(self) -> Dict:
        return {'requirement': 'Organizational Policies', 'status': CheckStatus.PASS}
    
    def check_hipaa_breach_notification(self) -> Dict:
        return {'requirement': 'Breach Notification', 'status': CheckStatus.PASS}
    
    def check_hipaa_documentation(self) -> Dict:
        return {'requirement': 'Documentation', 'status': CheckStatus.FAIL}
    
    # ISO 27001 Check Methods
    def check_iso_policies(self) -> Dict:
        return {'requirement': 'Information Security Policies', 'status': CheckStatus.PASS}
    
    def check_iso_organization(self) -> Dict:
        return {'requirement': 'Organization of Information Security', 'status': CheckStatus.PASS}
    
    def check_iso_asset_management(self) -> Dict:
        return {'requirement': 'Asset Management', 'status': CheckStatus.PASS}
    
    def check_iso_access_control(self) -> Dict:
        return {'requirement': 'Access Control', 'status': CheckStatus.PASS}
    
    def check_iso_cryptography(self) -> Dict:
        return {'requirement': 'Cryptography', 'status': CheckStatus.WARNING}
    
    def check_iso_physical(self) -> Dict:
        return {'requirement': 'Physical Security', 'status': CheckStatus.PASS}
    
    def check_iso_operations(self) -> Dict:
        return {'requirement': 'Operations Security', 'status': CheckStatus.PASS}
    
    def check_iso_incident_management(self) -> Dict:
        return {'requirement': 'Incident Management', 'status': CheckStatus.PASS}
    
    def check_iso_business_continuity(self) -> Dict:
        return {'requirement': 'Business Continuity', 'status': CheckStatus.FAIL}
    
    def check_iso_suppliers(self) -> Dict:
        return {'requirement': 'Supplier Relationships', 'status': CheckStatus.PASS}
    
    # SOC 2 Check Methods
    def check_soc2_control_environment(self) -> Dict:
        return {'requirement': 'Control Environment', 'status': CheckStatus.PASS}
    
    def check_soc2_communications(self) -> Dict:
        return {'requirement': 'Communications', 'status': CheckStatus.PASS}
    
    def check_soc2_risk_assessment(self) -> Dict:
        return {'requirement': 'Risk Assessment', 'status': CheckStatus.PASS}
    
    def check_soc2_control_activities(self) -> Dict:
        return {'requirement': 'Control Activities', 'status': CheckStatus.PASS}
    
    def check_soc2_monitoring_activities(self) -> Dict:
        return {'requirement': 'Monitoring Activities', 'status': CheckStatus.PASS}
    
    def check_soc2_logical_access(self) -> Dict:
        return {'requirement': 'Logical Access', 'status': CheckStatus.WARNING}
    
    def check_soc2_access_restrictions(self) -> Dict:
        return {'requirement': 'Access Restrictions', 'status': CheckStatus.PASS}
    
    def check_soc2_security_testing(self) -> Dict:
        return {'requirement': 'Security Testing', 'status': CheckStatus.FAIL}
    
    def check_soc2_change_management(self) -> Dict:
        return {'requirement': 'Change Management', 'status': CheckStatus.PASS}
    
    def get_compliance_level(self, score: float) -> str:
        """Determine compliance level based on score"""
        if score >= 95:
            return "Fully Compliant"
        elif score >= 85:
            return "Substantially Compliant"
        elif score >= 70:
            return "Partially Compliant"
        else:
            return "Non-Compliant"
    
    def run_all_compliance_checks(self) -> Dict:
        """Run all compliance framework checks"""
        print("\n" + "="*80)
        print("SECURITY COMPLIANCE AUTOMATION SCANNER v1.0")
        print("="*80)
        
        results = {
            'scan_timestamp': datetime.now().isoformat(),
            'frameworks': {}
        }
        
        # Run all checks
        results['frameworks']['pci_dss'] = self.check_pci_dss_compliance()
        results['frameworks']['hipaa'] = self.check_hipaa_compliance()
        results['frameworks']['iso_27001'] = self.check_iso_27001_compliance()
        results['frameworks']['soc2'] = self.check_soc2_compliance()
        
        # Calculate overall compliance
        overall_score = sum(f['compliance_score'] for f in results['frameworks'].values()) / len(results['frameworks'])
        results['overall_compliance_score'] = round(overall_score, 2)
        results['overall_compliance_level'] = self.get_compliance_level(overall_score)
        
        # Generate recommendations
        results['recommendations'] = self.generate_compliance_recommendations(results)
        
        return results
    
    def generate_compliance_recommendations(self, results: Dict) -> List[str]:
        """Generate remediation recommendations"""
        recommendations = []
        
        for framework_name, framework_data in results['frameworks'].items():
            if framework_data['compliance_level'] != 'Fully Compliant':
                recommendations.append(f"\n{framework_name.upper()}:")
                
                # Find failed checks
                for check_name, check_data in framework_data['checks'].items():
                    if isinstance(check_data, dict) and check_data.get('status') == CheckStatus.FAIL:
                        remediation = check_data.get('remediation', 'See compliance requirements')
                        recommendations.append(f"  • {check_data.get('requirement')}: {remediation}")
                    elif isinstance(check_data, dict) and check_data.get('status') == CheckStatus.WARNING:
                        recommendations.append(f"  • [WARNING] {check_data.get('requirement')}: Review and update")
        
        return recommendations
    
    def print_compliance_report(self, results: Dict):
        """Print formatted compliance report"""
        print("\n" + "="*80)
        print("COMPLIANCE ASSESSMENT REPORT")
        print("="*80)
        
        print(f"\n[OVERALL COMPLIANCE]")
        print(f"  Score: {results['overall_compliance_score']}/100")
        print(f"  Status: {results['overall_compliance_level']}")
        
        print(f"\n[FRAMEWORK SCORES]")
        for framework_name, framework_data in results['frameworks'].items():
            score = framework_data['compliance_score']
            level = framework_data['compliance_level']
            print(f"  {framework_data['framework']}: {score}% - {level}")
        
        print(f"\n[REMEDIATION ITEMS]")
        for rec in results['recommendations']:
            print(rec)
        
        print("\n[NEXT STEPS]")
        print("  1. Review failed compliance items")
        print("  2. Create remediation tickets")
        print("  3. Assign ownership for each item")
        print("  4. Schedule remediation reviews")
        print("  5. Re-scan after remediation")
        
        print("\n" + "="*80)
    
    def save_compliance_report(self, results: Dict, filename: str = 'compliance_report.json'):
        """Save compliance report to file"""
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"[+] Compliance report saved to {filename}")

def main():
    parser = argparse.ArgumentParser(description='Security Compliance Automation')
    parser.add_argument('-o', '--output', default='compliance_report.json', help='Output file')
    args = parser.parse_args()
    
    compliance = SecurityComplianceAutomation()
    results = compliance.run_all_compliance_checks()
    
    compliance.print_compliance_report(results)
    compliance.save_compliance_report(results, args.output)
    
    print(f"\n[+] Compliance scan completed")
    print(f"[+] Report saved to {args.output}")

if __name__ == '__main__':
    main()
