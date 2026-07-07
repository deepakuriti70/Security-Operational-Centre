"""
detector.py

This file contains all the "rules" our SOC dashboard uses to detect
suspicious activity in the logs. Each function looks at the logs in a
different way and returns a list of alerts if something looks wrong.

All detection here is simple rule-based logic (if/else and counting).
There is no AI or Machine Learning involved.
"""

from collections import defaultdict
from utils import read_blacklist, get_first_last_seen


# Thresholds used by our detection rules.
# These numbers can be changed later if the SOC team wants stricter rules.
BRUTE_FORCE_THRESHOLD = 5
PORT_SCAN_THRESHOLD = 8
FAILED_LOGIN_THRESHOLD = 3

# Business hours: anything outside this range is "off-hours"
OFFICE_START_HOUR = 6
OFFICE_END_HOUR = 22

# Usernames that are considered high value / sensitive accounts
ADMIN_USERNAMES = ["admin", "administrator", "root"]


def detect_brute_force(logs):
    """
    Rule 1: Brute Force Detection

    If a single IP address has more than BRUTE_FORCE_THRESHOLD failed
    login attempts, we raise a HIGH severity alert.
    """
    alerts = []
    failed_attempts_by_ip = defaultdict(int)

    # Count failed logins per IP address
    for log in logs:
        event_type = log.get("Event Type", "")
        status = log.get("Status", "")

        if event_type == "Login Failed" and status == "Failed":
            ip = log.get("IP Address")
            failed_attempts_by_ip[ip] += 1

    # Check which IPs went over the threshold
    for ip, count in failed_attempts_by_ip.items():
        if count > BRUTE_FORCE_THRESHOLD:
            first_seen, last_seen = get_first_last_seen(logs, ip=ip)
            alerts.append({
                "type": "Brute Force Attack",
                "severity": "High",
                "ip": ip,
                "description": f"IP {ip} generated {count} failed login attempts.",
                "recommendation": "Block this IP and force a password reset for the targeted accounts.",
                "first_seen": first_seen,
                "last_seen": last_seen
            })

    return alerts


def detect_port_scan(logs):
    """
    Rule 2: Port Scan Detection

    If a single IP address connects to more than PORT_SCAN_THRESHOLD
    different ports, we raise a HIGH severity alert.
    """
    alerts = []
    ports_by_ip = defaultdict(set)

    # Collect the unique ports each IP has touched
    for log in logs:
        ip = log.get("IP Address")
        port = log.get("Port")
        ports_by_ip[ip].add(port)

    # Check which IPs touched too many different ports
    for ip, port_set in ports_by_ip.items():
        if len(port_set) > PORT_SCAN_THRESHOLD:
            first_seen, last_seen = get_first_last_seen(logs, ip=ip)
            alerts.append({
                "type": "Port Scan",
                "severity": "High",
                "ip": ip,
                "description": f"IP {ip} accessed {len(port_set)} different ports.",
                "recommendation": "Investigate the source IP and consider blocking it at the firewall.",
                "first_seen": first_seen,
                "last_seen": last_seen
            })

    return alerts


def detect_blacklisted_ip(logs):
    """
    Rule 3: Blacklisted IP Detection

    Reads blacklist.txt and checks if any log entry comes from a known
    malicious IP address. If so, we raise a CRITICAL severity alert.
    """
    alerts = []
    blacklisted_ips = read_blacklist()
    already_alerted = set()

    for log in logs:
        ip = log.get("IP Address")

        if ip in blacklisted_ips and ip not in already_alerted:
            first_seen, last_seen = get_first_last_seen(logs, ip=ip)
            alerts.append({
                "type": "Blacklisted IP Activity",
                "severity": "Critical",
                "ip": ip,
                "description": f"Traffic detected from known malicious IP {ip}.",
                "recommendation": "Immediately block this IP at the perimeter firewall and escalate to Tier-2.",
                "first_seen": first_seen,
                "last_seen": last_seen
            })
            # We only want one alert per blacklisted IP, not one per log line
            already_alerted.add(ip)

    return alerts


def detect_multiple_failed_logins(logs):
    """
    Rule 4: Multiple Failed Login Detection (per user)

    If a single username fails to log in more than FAILED_LOGIN_THRESHOLD
    times, we raise a MEDIUM severity alert. This is different from the
    brute force rule because this rule looks at usernames, not IPs.
    """
    alerts = []
    failed_attempts_by_user = defaultdict(int)
    ip_for_user = {}

    for log in logs:
        event_type = log.get("Event Type", "")
        status = log.get("Status", "")

        if event_type == "Login Failed" and status == "Failed":
            username = log.get("Username")
            failed_attempts_by_user[username] += 1
            ip_for_user[username] = log.get("IP Address")

    for username, count in failed_attempts_by_user.items():
        if count > FAILED_LOGIN_THRESHOLD:
            first_seen, last_seen = get_first_last_seen(logs, username=username)
            alerts.append({
                "type": "Multiple Failed Logins",
                "severity": "Medium",
                "ip": ip_for_user.get(username, "Unknown"),
                "description": f"User '{username}' failed to log in {count} times.",
                "recommendation": "Verify with the user and consider a temporary account lockout.",
                "first_seen": first_seen,
                "last_seen": last_seen
            })

    return alerts


def detect_unauthorized_admin_login(logs):
    """
    Rule 5: Unauthorized Admin Login Detection

    Looks for failed login attempts using well known admin usernames
    such as admin, administrator, or root. These accounts are high
    value targets, so any failed attempt is treated as a HIGH alert.
    """
    alerts = []
    already_alerted = set()

    for log in logs:
        username = log.get("Username", "").lower()
        event_type = log.get("Event Type", "")
        status = log.get("Status", "")

        if username in ADMIN_USERNAMES and event_type == "Login Failed" and status == "Failed":
            ip = log.get("IP Address")
            alert_key = (ip, username)

            if alert_key not in already_alerted:
                first_seen, last_seen = get_first_last_seen(logs, ip=ip, username=log.get("Username"))
                alerts.append({
                    "type": "Unauthorized Admin Login Attempt",
                    "severity": "High",
                    "ip": ip,
                    "description": f"Failed login attempt on privileged account '{username}' from {ip}.",
                    "recommendation": "Confirm account status and enable multi-factor authentication.",
                    "first_seen": first_seen,
                    "last_seen": last_seen
                })
                already_alerted.add(alert_key)

    return alerts


def detect_off_hours_login(logs):
    """
    Rule 6: Off-Hours Login Detection

    Successful logins that happen very early or very late (outside
    normal office hours) are worth a second look, since attackers
    often operate when nobody is watching. Raises a LOW severity alert.
    """
    alerts = []

    for log in logs:
        if log.get("Event Type") == "Login Success":
            hour = int(log.get("Timestamp", "0000-00-00 00:00:00")[11:13])

            if hour < OFFICE_START_HOUR or hour >= OFFICE_END_HOUR:
                alerts.append({
                    "type": "Off-Hours Login",
                    "severity": "Low",
                    "ip": log.get("IP Address"),
                    "description": f"User '{log.get('Username')}' logged in at {log.get('Timestamp')}, outside normal office hours.",
                    "recommendation": "Confirm this login was expected with the user.",
                    "first_seen": log.get("Timestamp"),
                    "last_seen": log.get("Timestamp")
                })

    return alerts


def detect_user_multiple_ips(logs):
    """
    Rule 7: Same User, Multiple IPs Detection

    If one username successfully logs in from more than one different
    IP address, this could mean the password is shared or compromised.
    Raises a MEDIUM severity alert.
    """
    alerts = []
    ips_by_user = defaultdict(set)

    for log in logs:
        if log.get("Event Type") == "Login Success":
            ips_by_user[log.get("Username")].add(log.get("IP Address"))

    for username, ip_set in ips_by_user.items():
        if len(ip_set) > 1:
            first_seen, last_seen = get_first_last_seen(logs, username=username)
            alerts.append({
                "type": "Multiple IPs for One User",
                "severity": "Medium",
                "ip": ", ".join(ip_set),
                "description": f"User '{username}' logged in successfully from {len(ip_set)} different IPs.",
                "recommendation": "Verify with the user and consider enabling multi-factor authentication.",
                "first_seen": first_seen,
                "last_seen": last_seen
            })

    return alerts


def run_all_detections(logs):
    """
    Runs every detection rule and combines all the alerts into one list.
    This is the main function that app.py will call.
    """
    all_alerts = []

    all_alerts.extend(detect_brute_force(logs))
    all_alerts.extend(detect_port_scan(logs))
    all_alerts.extend(detect_blacklisted_ip(logs))
    all_alerts.extend(detect_multiple_failed_logins(logs))
    all_alerts.extend(detect_unauthorized_admin_login(logs))
    all_alerts.extend(detect_off_hours_login(logs))
    all_alerts.extend(detect_user_multiple_ips(logs))

    return all_alerts
