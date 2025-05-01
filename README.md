# SOC Automation Scripts

A collection of Python-based scripts built for automating common Security Operations Center (SOC) tasks — from log parsing and alert triage to Zabbix uptime reporting and IOC correlation.

## 🔍 What’s Inside

- `log_parser.py`: Extracts relevant security events from raw syslogs (firewalls, NIDS/HIDS)
- `ioc_enricher.py`: Looks up IOCs in VirusTotal or AbuseIPDB and enriches alert data
- `zabbix_uptime_report.py`: Pulls uptime history from Zabbix API and exports to Excel
- `alert_triage.py`: Filters alerts by severity, source IP, or known attack patterns
- `auto_es_alert.py`: Sends alerts to Elasticsearch for SIEM correlation

## ⚙️ Technologies
- Python 3
- Requests / Pandas / OpenPyXL
- Elasticsearch / Zabbix API / AbuseIPDB
- Copilot-assisted code generation

## 🧠 Ideal Use Cases
- Overloaded SOCs or part-time security teams
- Automating recurring triage and reporting tasks
- Building a lightweight SIEM workflow without Splunk costs

## 🚀 Get Started
```bash
git clone https://github.com/yourusername/SOC-Automation-Scripts.git
cd SOC-Automation-Scripts
pip install -r requirements.txt
python log_parser.py --input firewall.log
