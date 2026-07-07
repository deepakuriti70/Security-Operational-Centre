"""
app.py

This is the main Flask application file. It contains all the web
routes (pages) for the SOC Log Analyzer & Incident Detection Dashboard.

Routes:
    /            -> Dashboard (main page with stats and cards)
    /alerts      -> Alerts page (full table of all alerts)
    /logs        -> Logs page (raw log entries, optionally filtered by status)
    /report      -> Incident report page (text report)
    /generate    -> Generates a new incident report and redirects back

Run this file with:
    python app.py
"""

from flask import Flask, render_template, redirect, url_for, request
from utils import read_logs, search_logs, remove_old_logs, count_logs_by_date
from detector import run_all_detections
from analyzer import build_dashboard_data, get_all_alerts_sorted
from report import generate_incident_report, read_report_text

# Create the Flask application
app = Flask(__name__)


@app.route("/")
def dashboard():
    """
    Home page / Dashboard.
    Shows total logs, total alerts, severity counts, recent logs and
    recent alerts so the analyst gets a quick overview.
    """
    dashboard_data = build_dashboard_data()

    return render_template(
        "index.html",
        total_logs=dashboard_data["total_logs"],
        total_alerts=dashboard_data["total_alerts"],
        failed_logins=dashboard_data["failed_logins"],
        blocked_events=dashboard_data["blocked_events"],
        severity_count=dashboard_data["severity_count"],
        recent_logs=dashboard_data["recent_logs"],
        recent_alerts=dashboard_data["recent_alerts"],
        top_ips=dashboard_data["top_ips"]
    )


@app.route("/alerts")
def alerts_page():
    """
    Alerts page.
    Shows every alert that was detected, sorted from most severe to
    least severe. Supports two optional URL filters:
      - severity=critical/high/medium/low -> filter by severity
      - search=<text>                     -> find alerts by IP address
    """
    all_alerts = get_all_alerts_sorted()
    severity_filter = request.args.get("severity")
    search_text = request.args.get("search")

    if severity_filter:
        all_alerts = [a for a in all_alerts if a["severity"].lower() == severity_filter.lower()]

    if search_text:
        all_alerts = [a for a in all_alerts if search_text.lower() in a["ip"].lower()]

    return render_template(
        "alerts.html",
        alerts=all_alerts,
        total_alerts=len(all_alerts),
        severity_filter=severity_filter,
        search_text=search_text
    )


@app.route("/logs")
def logs_page():
    """
    Logs page.
    Shows the raw log entries from logs.csv. Supports three optional
    URL filters:
      - status=Failed/Blocked/Success -> filter by status
      - search=<text>                 -> find logs by IP or username
      - date=YYYY-MM-DD               -> show only logs from that day
    Also shows a day-by-day log count so an analyst can see which
    dates had the most activity.
    """
    all_logs = read_logs()
    status_filter = request.args.get("status")
    search_text = request.args.get("search")
    date_filter = request.args.get("date")

    date_counts = count_logs_by_date(all_logs)

    if status_filter:
        all_logs = [log for log in all_logs if log.get("Status") == status_filter]

    if search_text:
        all_logs = search_logs(all_logs, search_text)

    if date_filter:
        all_logs = [log for log in all_logs if log.get("Timestamp", "").startswith(date_filter)]

    return render_template(
        "logs.html",
        logs=all_logs,
        total_logs=len(all_logs),
        status_filter=status_filter,
        search_text=search_text,
        date_filter=date_filter,
        date_counts=date_counts
    )


@app.route("/report")
def report_page():
    """
    Report page.
    Displays the contents of reports/incident_report.txt in the browser.
    """
    report_text = read_report_text()

    return render_template(
        "report.html",
        report_text=report_text
    )


@app.route("/generate")
def generate_report_route():
    """
    Generates a brand new incident report based on the current logs
    and alerts, then redirects the analyst to the report page so they
    can see the result immediately.
    """
    logs = read_logs()
    alerts = run_all_detections(logs)
    generate_incident_report(alerts)

    return redirect(url_for("report_page"))


# This block only runs when we start the app directly with "python app.py"
if __name__ == "__main__":
    remove_old_logs()  # Keep only the last 30 days of logs before starting
    app.run(host="0.0.0.0", port=5000)
    app.run(debug=True)

