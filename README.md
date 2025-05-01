# SOC Automation Scripts

A collection of Python-based scripts to automate repetitive SOC tasks like log parsing and uptime reporting.

## 📂 Scripts Included

### 🔸 log_parser.py
Search and filter syslog/firewall logs for keywords like "failed", "unauthorized", "ssh", etc.

```bash
python log_parser.py --file auth.log --keyword failed
```

### 🔸 zabbix_uptime_report.py
Connects to Zabbix API, extracts icmpping status for hosts in a group, and exports results to Excel.

```bash
pip install requests pandas openpyxl
python zabbix_uptime_report.py
```

## 🔧 Requirements

- Python 3.x
- requests
- pandas
- openpyxl

## ✉️ Contact

If you'd like custom scripts for your logs or SOC tools, contact me at [LinkedIn](https://linkedin.com/in/josephkibaki) or [Fiverr](https://fiverr.com).
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
![Maintained](https://img.shields.io/badge/status-maintained-brightgreen)
