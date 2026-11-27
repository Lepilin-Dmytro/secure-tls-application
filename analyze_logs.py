import json
import re
from collections import Counter, defaultdict
from pathlib import Path

LOG_FILE = Path("logs/server.log")
FAILURE_THRESHOLD = 3

def analyze():
    if not LOG_FILE.exists():
        print(f"[ERROR] Log file not found: {LOG_FILE}")
        return

    events = Counter()
    failed_by_ip = Counter()
    failed_by_user = Counter()
    malformed = 0
    total = 0

    pattern = re.compile(
        r"^(.*?)\s+INFO\s+([A-Z_]+)\s+(\{.*\})$"
    )

    with LOG_FILE.open("r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if not line:
                continue

            match = pattern.match(line)
            if not match:
                malformed += 1
                continue

            timestamp, event, raw_data = match.groups()

            try:
                data = json.loads(raw_data)
            except json.JSONDecodeError:
                malformed += 1
                continue

            total += 1
            events[event] += 1

            if event == "AUTH_FAILED":
                failed_by_ip[data.get("ip", "unknown")] += 1
                failed_by_user[data.get("username", "unknown")] += 1

    print("\n========== TLS SECURITY LOG ANALYSIS ==========")
    print(f"Total valid events: {total}")
    print(f"Malformed records: {malformed}")

    print("\nEvent statistics:")
    for event, count in sorted(events.items()):
        print(f"  {event}: {count}")

    print("\nAuthentication:")
    print(f"  Successful: {events['AUTH_SUCCESS']}")
    print(f"  Failed:     {events['AUTH_FAILED']}")

    print("\nSuspicious activity:")
    alerts = 0

    for ip, count in failed_by_ip.items():
        if count >= FAILURE_THRESHOLD:
            print(f"  [ALERT] {count} failed logins from IP {ip}")
            alerts += 1

    for username, count in failed_by_user.items():
        if count >= FAILURE_THRESHOLD:
            print(f"  [ALERT] {count} failed logins for user {username}")
            alerts += 1

    if alerts == 0:
        print("  No repeated authentication failures detected.")

    report = {
        "total_events": total,
        "malformed_records": malformed,
        "event_statistics": dict(events),
        "successful_authentication": events["AUTH_SUCCESS"],
        "failed_authentication": events["AUTH_FAILED"],
        "failed_attempts_by_ip": dict(failed_by_ip),
        "failed_attempts_by_user": dict(failed_by_user),
        "alerts": alerts
    }

    Path("logs/analysis_report.json").write_text(
        json.dumps(report, indent=4),
        encoding="utf-8"
    )

    print("\nReport saved to logs/analysis_report.json")
    print("===============================================\n")


if __name__ == "__main__":
    analyze()
