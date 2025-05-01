import re
import argparse

def parse_log_line(line):
    pattern = r'(?P<timestamp>\w{3} \d{1,2} \d{2}:\d{2}:\d{2}) (?P<host>\S+) (?P<source>[^:]+): (?P<message>.*)'
    match = re.match(pattern, line)
    if match:
        return match.groupdict()
    return None

def filter_logs(file_path, keyword):
    with open(file_path, 'r') as f:
        for line in f:
            parsed = parse_log_line(line)
            if parsed and keyword.lower() in parsed['message'].lower():
                print(f"[{parsed['timestamp']}] {parsed['source']}: {parsed['message']}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Basic syslog keyword filter.")
    parser.add_argument('--file', required=True, help="Path to log file")
    parser.add_argument('--keyword', required=True, help="Keyword to search (e.g. failed, root, ssh)")
    args = parser.parse_args()

    filter_logs(args.file, args.keyword)