import pandas as pd
import re
from datetime import datetime

class LogAnalyzer:
    def __init__(self):
        self.common_patterns = {
            'ip_address': r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
            'timestamp': r'\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}',
            'error': r'error|failure|failed|warn|critical',
            'attack': r'attack|exploit|injection|overflow|xss|sql\s+injection'
        }

    def parse_log(self, log_content):
        try:
            # Split log into lines
            lines = log_content.splitlines()
            parsed_logs = []

            for line in lines:
                log_entry = {
                    'timestamp': self._extract_timestamp(line),
                    'ip_address': self._extract_ip(line),
                    'message': line,
                    'severity': self._determine_severity(line),
                    'attack_indicators': self._check_attack_indicators(line)
                }
                parsed_logs.append(log_entry)

            return pd.DataFrame(parsed_logs)
        except Exception as e:
            raise Exception(f"Error parsing log: {str(e)}")

    def _extract_timestamp(self, line):
        match = re.search(self.common_patterns['timestamp'], line)
        return match.group(0) if match else None

    def _extract_ip(self, line):
        match = re.search(self.common_patterns['ip_address'], line)
        return match.group(0) if match else None

    def _determine_severity(self, line):
        if re.search(r'critical|error', line.lower()):
            return 'HIGH'
        elif re.search(r'warn|warning', line.lower()):
            return 'MEDIUM'
        return 'LOW'

    def _check_attack_indicators(self, line):
        match = re.search(self.common_patterns['attack'], line.lower())
        return bool(match)

    def get_basic_stats(self, df):
        return {
            'total_entries': len(df),
            'unique_ips': df['ip_address'].nunique(),
            'high_severity': len(df[df['severity'] == 'HIGH']),
            'potential_attacks': len(df[df['attack_indicators'] == True])
        }
