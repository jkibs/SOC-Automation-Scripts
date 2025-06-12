#!/usr/bin/env python3
"""
Zabbix-AbuseIPDB Threat Intelligence Correlator
===============================================
Correlates Zabbix alerts with AbuseIPDB threat feeds to enhance SOC incident response.
Automatically enriches security events with threat intelligence data.

Author: J-Kibaki
Requirements: requests, python-dotenv, logging
"""

import requests
import json
import logging
import time
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

@dataclass
class ZabbixAlert:
    """Represents a Zabbix alert with relevant fields"""
    alert_id: str
    hostname: str
    trigger_name: str
    severity: str
    timestamp: datetime
    description: str
    source_ip: Optional[str] = None
    event_value: str = "1"

@dataclass
class ThreatIntelligence:
    """Represents threat intelligence data from AbuseIPDB"""
    ip_address: str
    abuse_confidence: int
    country_code: str
    usage_type: str
    isp: str
    is_whitelisted: bool
    total_reports: int
    last_reported: Optional[datetime]
    categories: List[str]

class ZabbixAPI:
    """Zabbix API client for fetching alerts and problems"""
    
    def __init__(self, url: str, username: str, password: str):
        self.url = url.rstrip('/') + '/api_jsonrpc.php'
        self.username = username
        self.password = password
        self.auth_token = None
        self.session = requests.Session()
        
    def authenticate(self) -> bool:
        """Authenticate with Zabbix API"""
        payload = {
            "jsonrpc": "2.0",
            "method": "user.login",
            "params": {
                "user": self.username,
                "password": self.password
            },
            "id": 1
        }
        
        try:
            response = self.session.post(self.url, json=payload)
            response.raise_for_status()
            result = response.json()
            
            if 'result' in result:
                self.auth_token = result['result']
                logging.info("Successfully authenticated with Zabbix API")
                return True
            else:
                logging.error(f"Authentication failed: {result.get('error', 'Unknown error')}")
                return False
                
        except Exception as e:
            logging.error(f"Zabbix authentication error: {e}")
            return False
    
    def get_recent_problems(self, hours: int = 24) -> List[ZabbixAlert]:
        """Fetch recent problems from Zabbix"""
        if not self.auth_token:
            if not self.authenticate():
                return []
        
        # Calculate timestamp for filtering
        time_from = int((datetime.now() - timedelta(hours=hours)).timestamp())
        
        payload = {
            "jsonrpc": "2.0",
            "method": "problem.get",
            "params": {
                "output": ["eventid", "objectid", "name", "severity", "clock", "r_eventid"],
                "selectHosts": ["hostid", "name", "host"],
                "selectTriggers": ["triggerid", "description", "priority"],
                "time_from": time_from,
                "recent": True,
                "sortfield": ["clock"],
                "sortorder": "DESC"
            },
            "auth": self.auth_token,
            "id": 2
        }
        
        try:
            response = self.session.post(self.url, json=payload)
            response.raise_for_status()
            result = response.json()
            
            alerts = []
            if 'result' in result:
                for problem in result['result']:
                    # Extract IP addresses from trigger name/description
                    source_ip = self._extract_ip_address(
                        problem.get('name', '') + ' ' + 
                        problem.get('triggers', [{}])[0].get('description', '')
                    )
                    
                    alert = ZabbixAlert(
                        alert_id=problem['eventid'],
                        hostname=problem.get('hosts', [{}])[0].get('name', 'Unknown'),
                        trigger_name=problem['name'],
                        severity=self._map_severity(problem['severity']),
                        timestamp=datetime.fromtimestamp(int(problem['clock'])),
                        description=problem.get('triggers', [{}])[0].get('description', ''),
                        source_ip=source_ip
                    )
                    alerts.append(alert)
                    
            logging.info(f"Retrieved {len(alerts)} recent problems from Zabbix")
            return alerts
            
        except Exception as e:
            logging.error(f"Error fetching Zabbix problems: {e}")
            return []
    
    def _extract_ip_address(self, text: str) -> Optional[str]:
        """Extract IP address from text using regex"""
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        matches = re.findall(ip_pattern, text)
        return matches[0] if matches else None
    
    def _map_severity(self, severity: str) -> str:
        """Map Zabbix severity numbers to readable strings"""
        severity_map = {
            "0": "Not classified",
            "1": "Information",
            "2": "Warning", 
            "3": "Average",
            "4": "High",
            "5": "Disaster"
        }
        return severity_map.get(severity, "Unknown")

class AbuseIPDBClient:
    """AbuseIPDB API client for threat intelligence queries"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.session = requests.Session()
        self.session.headers.update({
            'Key': self.api_key,
            'Accept': 'application/json'
        })
        
    def check_ip(self, ip_address: str, max_age_days: int = 90) -> Optional[ThreatIntelligence]:
        """Check IP address against AbuseIPDB"""
        url = f"{self.base_url}/check"
        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': max_age_days,
            'verbose': ''
        }
        
        try:
            response = self.session.get(url, params=params)
            response.raise_for_status()
            data = response.json()
            
            if 'data' in data:
                result = data['data']
                
                # Parse last reported date
                last_reported = None
                if result.get('lastReportedAt'):
                    last_reported = datetime.fromisoformat(
                        result['lastReportedAt'].replace('Z', '+00:00')
                    )
                
                # Map category codes to descriptions
                categories = self._map_categories(result.get('categories', []))
                
                return ThreatIntelligence(
                    ip_address=ip_address,
                    abuse_confidence=result.get('abuseConfidencePercentage', 0),
                    country_code=result.get('countryCode', 'Unknown'),
                    usage_type=result.get('usageType', 'Unknown'),
                    isp=result.get('isp', 'Unknown'),
                    is_whitelisted=result.get('isWhitelisted', False),
                    total_reports=result.get('totalReports', 0),
                    last_reported=last_reported,
                    categories=categories
                )
                
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 429:
                logging.warning(f"Rate limit exceeded for IP {ip_address}")
                time.sleep(1)  # Brief pause for rate limiting
            else:
                logging.error(f"HTTP error checking IP {ip_address}: {e}")
        except Exception as e:
            logging.error(f"Error checking IP {ip_address}: {e}")
            
        return None
    
    def _map_categories(self, category_codes: List[int]) -> List[str]:
        """Map AbuseIPDB category codes to descriptions"""
        category_map = {
            1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders",
            4: "DDoS Attack", 5: "FTP Brute-Force", 6: "Ping of Death",
            7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy", 10: "Web Spam",
            11: "Email Spam", 12: "Blog Spam", 13: "VPN IP", 14: "Port Scan",
            15: "Hacking", 16: "SQL Injection", 17: "Spoofing", 18: "Brute-Force",
            19: "Bad Web Bot", 20: "Exploited Host", 21: "Web App Attack",
            22: "SSH", 23: "IoT Targeted"
        }
        return [category_map.get(code, f"Unknown ({code})") for code in category_codes]

class ThreatCorrelator:
    """Main class for correlating Zabbix alerts with AbuseIPDB threat intelligence"""
    
    def __init__(self, zabbix_client: ZabbixAPI, abuseipdb_client: AbuseIPDBClient):
        self.zabbix = zabbix_client
        self.abuseipdb = abuseipdb_client
        self.correlation_results = []
        
    def correlate_threats(self, hours_back: int = 24) -> List[Dict]:
        """Correlate recent Zabbix alerts with AbuseIPDB threat intelligence"""
        logging.info(f"Starting threat correlation for last {hours_back} hours")
        
        # Get recent alerts from Zabbix
        alerts = self.zabbix.get_recent_problems(hours_back)
        
        if not alerts:
            logging.warning("No alerts found in Zabbix")
            return []
        
        correlations = []
        
        for alert in alerts:
            if not alert.source_ip:
                continue
                
            logging.info(f"Checking threat intelligence for IP: {alert.source_ip}")
            
            # Get threat intelligence
            threat_info = self.abuseipdb.check_ip(alert.source_ip)
            
            if threat_info:
                risk_score = self._calculate_risk_score(alert, threat_info)
                
                correlation = {
                    'alert_id': alert.alert_id,
                    'hostname': alert.hostname,
                    'trigger_name': alert.trigger_name,
                    'severity': alert.severity,
                    'timestamp': alert.timestamp.isoformat(),
                    'source_ip': alert.source_ip,
                    'threat_intelligence': {
                        'abuse_confidence': threat_info.abuse_confidence,
                        'country': threat_info.country_code,
                        'isp': threat_info.isp,
                        'usage_type': threat_info.usage_type,
                        'total_reports': threat_info.total_reports,
                        'categories': threat_info.categories,
                        'is_whitelisted': threat_info.is_whitelisted,
                        'last_reported': threat_info.last_reported.isoformat() if threat_info.last_reported else None
                    },
                    'risk_score': risk_score,
                    'recommendation': self._get_recommendation(risk_score, threat_info)
                }
                
                correlations.append(correlation)
                
                # Rate limiting
                time.sleep(0.5)
        
        self.correlation_results = correlations
        logging.info(f"Completed correlation for {len(correlations)} alerts with IP addresses")
        return correlations
    
    def _calculate_risk_score(self, alert: ZabbixAlert, threat_info: ThreatIntelligence) -> int:
        """Calculate risk score based on alert severity and threat intelligence"""
        base_score = 0
        
        # Severity scoring
        severity_scores = {
            "Information": 1,
            "Warning": 2,
            "Average": 3,
            "High": 4,
            "Disaster": 5
        }
        base_score += severity_scores.get(alert.severity, 0) * 10
        
        # Threat intelligence scoring
        base_score += threat_info.abuse_confidence
        
        # Additional factors
        if threat_info.total_reports > 100:
            base_score += 10
        if threat_info.total_reports > 1000:
            base_score += 20
            
        # Category-based risk
        high_risk_categories = ["Hacking", "Brute-Force", "DDoS Attack", "Web App Attack"]
        if any(cat in threat_info.categories for cat in high_risk_categories):
            base_score += 15
            
        # Recent activity
        if threat_info.last_reported and threat_info.last_reported > datetime.now() - timedelta(days=7):
            base_score += 10
            
        return min(base_score, 100)  # Cap at 100
    
    def _get_recommendation(self, risk_score: int, threat_info: ThreatIntelligence) -> str:
        """Generate recommendation based on risk score and threat data"""
        if risk_score >= 80:
            return "CRITICAL: Immediate investigation required. Consider blocking IP."
        elif risk_score >= 60:
            return "HIGH: Priority investigation. Monitor closely."
        elif risk_score >= 40:
            return "MEDIUM: Schedule investigation. Review logs."
        elif risk_score >= 20:
            return "LOW: Log for reference. Routine monitoring."
        else:
            return "INFO: Minimal risk detected. Standard monitoring."
    
    def generate_report(self, output_file: str = None) -> str:
        """Generate a detailed threat correlation report"""
        if not self.correlation_results:
            return "No correlation results available. Run correlate_threats() first."
        
        report_lines = [
            "=" * 80,
            "ZABBIX-ABUSEIPDB THREAT CORRELATION REPORT",
            "=" * 80,
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Total Correlations: {len(self.correlation_results)}",
            ""
        ]
        
        # Summary statistics
        high_risk = sum(1 for r in self.correlation_results if r['risk_score'] >= 60)
        medium_risk = sum(1 for r in self.correlation_results if 40 <= r['risk_score'] < 60)
        low_risk = sum(1 for r in self.correlation_results if r['risk_score'] < 40)
        
        report_lines.extend([
            "RISK SUMMARY:",
            f"  High Risk (60+):    {high_risk}",
            f"  Medium Risk (40-59): {medium_risk}",
            f"  Low Risk (<40):     {low_risk}",
            "",
            "DETAILED CORRELATIONS:",
            "-" * 80
        ])
        
        # Sort by risk score (highest first)
        sorted_results = sorted(self.correlation_results, key=lambda x: x['risk_score'], reverse=True)
        
        for result in sorted_results:
            ti = result['threat_intelligence']
            report_lines.extend([
                f"Alert ID: {result['alert_id']} | Risk Score: {result['risk_score']}/100",
                f"Host: {result['hostname']}",
                f"Trigger: {result['trigger_name']}",
                f"Source IP: {result['source_ip']} ({ti['country']}) - {ti['isp']}",
                f"Abuse Confidence: {ti['abuse_confidence']}% | Reports: {ti['total_reports']}",
                f"Categories: {', '.join(ti['categories']) if ti['categories'] else 'None'}",
                f"Recommendation: {result['recommendation']}",
                f"Timestamp: {result['timestamp']}",
                "-" * 80
            ])
        
        report = "\n".join(report_lines)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(report)
            logging.info(f"Report saved to {output_file}")
        
        return report

def main():
    """Main execution function"""
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('zabbix_threat_correlation.log'),
            logging.StreamHandler()
        ]
    )
    
    # Load configuration from environment variables
    zabbix_url = os.getenv('ZABBIX_URL', 'http://localhost/zabbix')
    zabbix_user = os.getenv('ZABBIX_USERNAME', 'admin')
    zabbix_pass = os.getenv('ZABBIX_PASSWORD', 'password')
    abuseipdb_key = os.getenv('ABUSEIPDB_API_KEY')
    
    if not abuseipdb_key:
        logging.error("ABUSEIPDB_API_KEY environment variable not set")
        return
    
    try:
        # Initialize clients
        zabbix_client = ZabbixAPI(zabbix_url, zabbix_user, zabbix_pass)
        abuseipdb_client = AbuseIPDBClient(abuseipdb_key)
        
        # Create correlator
        correlator = ThreatCorrelator(zabbix_client, abuseipdb_client)
        
        # Perform correlation
        results = correlator.correlate_threats(hours_back=24)
        
        if results:
            # Generate and display report
            report = correlator.generate_report(f"threat_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
            print(report)
            
            # Export results as JSON
            with open(f"correlations_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json", 'w') as f:
                json.dump(results, f, indent=2, default=str)
                
        else:
            logging.info("No correlations found")
            
    except Exception as e:
        logging.error(f"Script execution error: {e}")

if __name__ == "__main__":
    main()