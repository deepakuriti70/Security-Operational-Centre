"""
analyzer.py

This file takes the raw logs and the alerts produced by detector.py and
turns them into useful statistics for the dashboard. Think of this file
as the "brain" that summarizes everything for the analyst.
"""

from collections import Counter
from utils import read_logs, get_recent_logs
from detector import run_all_detections


def count_alerts_by_severity(alerts):
    """
    Counts how many alerts fall into each severity level.
    Returns a dictionary like:
    {"Critical": 2, "High": 5, "Medium": 3, "Low": 0}
    """
    severity_count = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0
    }

    for alert in alerts:
        severity = alert.get("severity", "Low")
        if severity in severity_count:
            severity_count[severity] += 1

    return severity_count


def get_top_source_ips(logs, limit=5):
    """
    Returns the IP addresses that appear most often in the logs.
    This helps the analyst quickly see which IPs are the noisiest.
    """
    ip_counter = Counter()

    for log in logs:
        ip = log.get("IP Address")
        ip_counter[ip] += 1

    # most_common() returns a list of tuples like [(ip, count), ...]
    return ip_counter.most_common(limit)


def get_event_type_summary(logs):
    """
    Returns a count of how many times each event type appears.
    Example: {"Login Success": 80, "Login Failed": 40, "Port Scan": 12}
    """
    event_counter = Counter()

    for log in logs:
        event_type = log.get("Event Type")
        event_counter[event_type] += 1

    return dict(event_counter)


def count_failed_logins(logs):
    """
    Counts how many log entries have a "Failed" status.
    This gives a quick sense of login activity, separate from alerts.
    """
    return len([log for log in logs if log.get("Status") == "Failed"])


def count_blocked_events(logs):
    """
    Counts how many log entries were "Blocked" (e.g. blocked port scans).
    """
    return len([log for log in logs if log.get("Status") == "Blocked"])


def build_dashboard_data():
    """
    Main function used by app.py to build all the data needed for the
    dashboard page. This keeps app.py clean and focused only on routes.
    """
    logs = read_logs()
    alerts = run_all_detections(logs)

    dashboard_data = {
        "total_logs": len(logs),
        "total_alerts": len(alerts),
        "failed_logins": count_failed_logins(logs),
        "blocked_events": count_blocked_events(logs),
        "severity_count": count_alerts_by_severity(alerts),
        "recent_logs": get_recent_logs(logs, limit=10),
        "recent_alerts": alerts[-10:][::-1],  # last 10 alerts, newest first
        "top_ips": get_top_source_ips(logs, limit=5),
        "event_summary": get_event_type_summary(logs),
        "all_alerts": alerts
    }

    return dashboard_data


def get_all_alerts_sorted():
    """
    Returns all alerts sorted so that the most severe alerts appear
    first. This is used on the Alerts page.
    """
    logs = read_logs()
    alerts = run_all_detections(logs)

    # We give each severity level a rank so we can sort by it
    severity_rank = {
        "Critical": 1,
        "High": 2,
        "Medium": 3,
        "Low": 4
    }

    sorted_alerts = sorted(alerts, key=lambda alert: severity_rank.get(alert.get("severity"), 5))
    return sorted_alerts
