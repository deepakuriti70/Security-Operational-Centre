"""
report.py

This file is responsible for writing the alerts out to a plain text
incident report. A real SOC team often needs a text file they can
attach to an email or a ticket, so this gives us that file.
"""

import os
from datetime import datetime
from utils import get_current_timestamp

REPORT_FOLDER = "reports"
REPORT_FILE_PATH = os.path.join(REPORT_FOLDER, "incident_report.txt")


def make_sure_report_folder_exists():
    """
    Creates the reports folder if it does not already exist.
    """
    if not os.path.exists(REPORT_FOLDER):
        os.makedirs(REPORT_FOLDER)


def build_report_header():
    """
    Builds the top section of the report with the date and time it
    was generated.
    """
    header_lines = []
    header_lines.append("=" * 60)
    header_lines.append("SOC INCIDENT REPORT")
    header_lines.append("=" * 60)
    header_lines.append(f"Generated On : {get_current_timestamp()}")
    header_lines.append("=" * 60)
    header_lines.append("")

    return "\n".join(header_lines)


def build_alert_block(alert, alert_number):
    """
    Builds the text block for a single alert. This is repeated for
    every alert in the report.
    """
    lines = []
    lines.append(f"INCIDENT #{alert_number}")
    lines.append("-" * 40)
    lines.append(f"Date/Time      : {get_current_timestamp()}")
    lines.append(f"Incident Type  : {alert.get('type')}")
    lines.append(f"Severity       : {alert.get('severity')}")
    lines.append(f"Affected IP    : {alert.get('ip')}")
    lines.append(f"First Seen     : {alert.get('first_seen')}")
    lines.append(f"Last Seen      : {alert.get('last_seen')}")
    lines.append(f"Description    : {alert.get('description')}")
    lines.append(f"Recommendation : {alert.get('recommendation')}")
    lines.append("")

    return "\n".join(lines)


def generate_incident_report(alerts):
    """
    Main function that writes all alerts into reports/incident_report.txt.
    This overwrites the file each time it is called so the report always
    reflects the latest analysis.
    """
    make_sure_report_folder_exists()

    report_text = build_report_header()

    if len(alerts) == 0:
        report_text += "No incidents detected during this analysis.\n"
    else:
        alert_number = 1
        for alert in alerts:
            report_text += build_alert_block(alert, alert_number)
            alert_number += 1

    # Add a short summary footer
    report_text += "=" * 60 + "\n"
    report_text += f"Total Incidents Found: {len(alerts)}\n"
    report_text += "=" * 60 + "\n"

    with open(REPORT_FILE_PATH, "w") as report_file:
        report_file.write(report_text)

    return REPORT_FILE_PATH


def read_report_text():
    """
    Reads the incident report file so it can be displayed on the
    report.html page. If the report does not exist yet, it returns
    a helpful message instead of crashing.
    """
    if not os.path.exists(REPORT_FILE_PATH):
        return "No report has been generated yet. Please run the analysis first."

    with open(REPORT_FILE_PATH, "r") as report_file:
        return report_file.read()
