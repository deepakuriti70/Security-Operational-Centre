"""
utils.py

This file contains small helper functions that are used by other files
in the project. Keeping these functions here makes the rest of the code
easier to read, because we do not repeat the same code everywhere.
"""

import csv
import os
from datetime import datetime, timedelta

# How many days of log history we keep before old entries are deleted
LOG_RETENTION_DAYS = 30


# Path to the main log file
LOG_FILE_PATH = "logs.csv"

# Path to the blacklist file
BLACKLIST_FILE_PATH = "blacklist.txt"


def read_logs():
    """
    Reads the logs.csv file and returns the logs as a list of dictionaries.
    Each dictionary represents one log line (one row from the CSV file).
    """
    logs = []

    # If the file does not exist, return an empty list instead of crashing
    if not os.path.exists(LOG_FILE_PATH):
        return logs

    with open(LOG_FILE_PATH, mode="r", newline="") as csv_file:
        csv_reader = csv.DictReader(csv_file)

        # Loop through every row and add it to our logs list
        for row in csv_reader:
            logs.append(row)

    return logs


def remove_old_logs():
    """
    Keeps only the last 30 days of logs, deleting anything older.

    The 30-day window is measured from the newest log entry we have,
    not from today's real-world date. This matters because our sample
    logs.csv has fixed dates - if we measured from the real clock,
    the very first time you ran this app on a different day, it
    could wipe out all the demo data. Measuring from the newest entry
    means the retention rule always works the same way, no matter
    when the app is run.
    """
    logs = read_logs()
    if not logs:
        return

    newest_timestamp = max(datetime.strptime(log["Timestamp"], "%Y-%m-%d %H:%M:%S") for log in logs)
    cutoff = newest_timestamp - timedelta(days=LOG_RETENTION_DAYS)

    recent_logs = [
        log for log in logs
        if datetime.strptime(log["Timestamp"], "%Y-%m-%d %H:%M:%S") >= cutoff
    ]

    # Only rewrite the file if something was actually removed
    if len(recent_logs) < len(logs):
        with open(LOG_FILE_PATH, mode="w", newline="") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=recent_logs[0].keys())
            writer.writeheader()
            writer.writerows(recent_logs)


def count_logs_by_date(logs):
    """
    Groups logs by their date (ignoring the time) and counts how many
    happened on each day. Returns a list like:
    [("2026-07-01", 42), ("2026-07-02", 38), ...] sorted oldest first.
    """
    counts_by_date = {}

    for log in logs:
        date_only = log.get("Timestamp", "")[:10]
        counts_by_date[date_only] = counts_by_date.get(date_only, 0) + 1

    return sorted(counts_by_date.items())


def read_blacklist():
    """
    Reads the blacklist.txt file and returns a list of blacklisted IP
    addresses. Blank lines are ignored.
    """
    blacklisted_ips = []

    if not os.path.exists(BLACKLIST_FILE_PATH):
        return blacklisted_ips

    with open(BLACKLIST_FILE_PATH, mode="r") as text_file:
        for line in text_file:
            ip_address = line.strip()
            if ip_address != "":
                blacklisted_ips.append(ip_address)

    return blacklisted_ips


def get_current_timestamp():
    """
    Returns the current date and time as a formatted string.
    This is used when writing the incident report.
    """
    from datetime import datetime
    now = datetime.now()
    return now.strftime("%Y-%m-%d %H:%M:%S")


def count_total_logs(logs):
    """
    Returns the total number of logs in the list.
    """
    return len(logs)


def get_unique_ips(logs):
    """
    Returns a list of unique IP addresses found in the logs.
    """
    ip_list = []

    for log in logs:
        ip = log.get("IP Address")
        if ip not in ip_list:
            ip_list.append(ip)

    return ip_list


def get_recent_logs(logs, limit=10):
    """
    Returns the most recent logs from the list.
    Since our logs.csv is already sorted by time, we simply take the
    last few rows and reverse them so the newest log appears first.
    """
    recent_logs = logs[-limit:]
    recent_logs.reverse()
    return recent_logs


def search_logs(logs, search_text):
    """
    Returns only the logs where the search text appears in the IP
    Address or Username (not case-sensitive). Used so an analyst can
    quickly find every log line related to a specific IP or user.
    """
    search_text = search_text.lower()
    matching_logs = []

    for log in logs:
        ip = log.get("IP Address", "").lower()
        username = log.get("Username", "").lower()

        if search_text in ip or search_text in username:
            matching_logs.append(log)

    return matching_logs


def get_first_last_seen(logs, ip=None, username=None):
    """
    Finds the first and last timestamp for logs matching a given IP
    and/or username. Used to show "First Seen" and "Last Seen" on an
    alert, so we know when an attack started and when it last happened.

    Note: our timestamps look like "2026-07-01 08:03:00", so comparing
    them as plain text with min()/max() still gives the correct order.
    """
    matching_timestamps = []

    for log in logs:
        if ip and log.get("IP Address") != ip:
            continue
        if username and log.get("Username") != username:
            continue
        matching_timestamps.append(log.get("Timestamp"))

    if not matching_timestamps:
        return None, None

    return min(matching_timestamps), max(matching_timestamps)


def safe_int(value, default=0):
    """
    Tries to convert a value to an integer.
    If it fails, it returns a default value instead of crashing the app.
    """
    try:
        return int(value)
    except (ValueError, TypeError):
        return default
