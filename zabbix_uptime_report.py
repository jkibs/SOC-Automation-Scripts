import requests
import json
import pandas as pd

ZABBIX_URL = 'https://your-zabbix-url/api_jsonrpc.php'
USERNAME = 'your-username'
PASSWORD = 'your-password'
GROUP_NAME = 'BRANCH ROUTERS'

def login():
    payload = {
        "jsonrpc": "2.0",
        "method": "user.login",
        "params": {"user": USERNAME, "password": PASSWORD},
        "id": 1
    }
    return requests.post(ZABBIX_URL, json=payload).json()['result']

def get_group_id(token, name):
    payload = {
        "jsonrpc": "2.0",
        "method": "hostgroup.get",
        "params": {"filter": {"name": [name]}},
        "auth": token, "id": 2
    }
    return requests.post(ZABBIX_URL, json=payload).json()['result'][0]['groupid']

def get_hosts(token, group_id):
    payload = {
        "jsonrpc": "2.0",
        "method": "host.get",
        "params": {
            "output": ["hostid", "host"],
            "groupids": group_id
        },
        "auth": token, "id": 3
    }
    return requests.post(ZABBIX_URL, json=payload).json()['result']

def get_uptime(token, host_id):
    payload = {
        "jsonrpc": "2.0",
        "method": "item.get",
        "params": {
            "output": "extend",
            "hostids": host_id,
            "search": {"key_": "icmpping"},
            "sortfield": "name"
        },
        "auth": token, "id": 4
    }
    return requests.post(ZABBIX_URL, json=payload).json()['result']

def main():
    token = login()
    group_id = get_group_id(token, GROUP_NAME)
    hosts = get_hosts(token, group_id)

    data = []
    for host in hosts:
        items = get_uptime(token, host['hostid'])
        for item in items:
            data.append({
                "Host": host['host'],
                "Item": item['name'],
                "Status": "Up" if item['lastvalue'] == '1' else "Down",
                "Last Check": item['lastclock']
            })

    df = pd.DataFrame(data)
    df.to_excel("zabbix_uptime_report.xlsx", index=False)
    print("✅ Report saved as zabbix_uptime_report.xlsx")

if __name__ == "__main__":
    main()