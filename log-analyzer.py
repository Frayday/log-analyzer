import re
import datetime
from collections import Counter

def analyze_logs(log_file_path, suspicious_patterns):
    """
    Analyzes log files for suspicious activities based on provided patterns.

    Args:
        log_file_path (str): The path to the log file.
        suspicious_patterns (list): A list of regular expressions representing suspicious activities.

    Returns:
        dict: A dictionary containing analysis results (suspicious events, IP counts, etc.).
    """

    try:
        with open(log_file_path, 'r') as f:
            log_lines = f.readlines()
    except FileNotFoundError:
        return {"error": f"Log file not found: {log_file_path}"}


    suspicious_events = []
    ip_addresses = Counter()  # Use a Counter to efficiently count IP occurrences
    timestamps = []

    for line in log_lines:
        for pattern in suspicious_patterns:
            match = re.search(pattern, line)
            if match:
                suspicious_events.append({"line": line.strip(), "pattern": pattern})


                # Extract IP address (improve this based on your log format)
                ip_match = re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", line)
                if ip_match:
                    ip_addresses[ip_match.group(0)] += 1

                # Extract timestamp (adapt to your log's timestamp format)  Example: 2023-10-27 10:00:00
                timestamp_match = re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", line)
                if timestamp_match:
                    try:
                        timestamps.append(datetime.datetime.strptime(timestamp_match.group(0), "%Y-%m-%d %H:%M:%S"))
                    except ValueError:
                        pass  # Handle invalid timestamp formats

    report = {
        "suspicious_events": suspicious_events,
        "ip_counts": ip_addresses.most_common(), # Most frequent IPs
        "total_suspicious_events": len(suspicious_events)
    }


    if timestamps:
        report["earliest_event"] = min(timestamps).strftime("%Y-%m-%d %H:%M:%S")
        report["latest_event"] = max(timestamps).strftime("%Y-%m-%d %H:%M:%S")

    return report




def main():
    log_file = "access.log"  # Replace with your log file path
    # Add more patterns as needed for different suspicious activities.
    suspicious_patterns = [
        r"Failed password for invalid user",  # SSH failed login (example)
        r"401 Unauthorized",
        r"Permission denied",
        r"Invalid user"
    ]

    report = analyze_logs(log_file, suspicious_patterns)

    if "error" in report:
        print(report["error"])
        return

    print("Log Analysis Report:")
    print("------------------")
    print(f"Total Suspicious Events: {report['total_suspicious_events']}")

    if report["ip_counts"]:
        print("\nTop Suspicious IP Addresses:")
        for ip, count in report['ip_counts']:
            print(f"  {ip}: {count} events")

    if "earliest_event" in report:
        print(f"\nEarliest Event: {report['earliest_event']}")
        print(f"Latest Event: {report['latest_event']}")



    if report["suspicious_events"]:
        print("\nSuspicious Events (Sample - Showing first 5):") # Show a sample
        for event in report['suspicious_events'][:5]: # Limit the output
            print(f"  Line: {event['line']}")
            print(f"  Pattern: {event['pattern']}")
            print("-" * 20)


if __name__ == "__main__":
    main()