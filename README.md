# SOC Log Analyzer & Incident Detection Dashboard

A beginner-friendly, rule-based Security Operations Center (SOC) dashboard built with **Python** and **Flask**. This project simulates the daily work of a Tier-1 SOC Analyst: reading raw security logs, detecting suspicious activity with simple detection rules, generating incident reports, and visualizing everything on a dark-themed web dashboard.

## Project Overview

This project was built to demonstrate practical, hands-on understanding of core SOC analyst concepts:

- Reading and parsing security logs
- Applying rule-based detection logic (no AI/ML)
- Classifying incidents by severity (Low, Medium, High, Critical)
- Writing incident reports
- Presenting findings on a clean, readable dashboard

It uses only **CSV files** for data storage — no database is required — which keeps the project simple, portable, and easy to explain in an interview.

## Features

- **Brute Force Detection** — flags any IP with more than 5 failed login attempts
- **Port Scan Detection** — flags any IP that touches more than 8 different ports
- **Blacklisted IP Detection** — cross-references traffic against a list of 20 known malicious IPs
- **Multiple Failed Login Detection** — flags accounts with repeated failed logins
- **Unauthorized Admin Login Detection** — flags failed attempts against admin/root/administrator accounts
- **Automatic Incident Report Generation** — writes a plain text report to `reports/incident_report.txt`
- **Dashboard** — total logs, total alerts, severity breakdown, recent alerts, recent logs, and top source IPs
- **Alerts Page** — full sortable list of every detected incident
- **Report Page** — view the generated incident report directly in the browser

## Tech Stack

**Backend:** Python 3.12, Flask
**Frontend:** HTML5, CSS3, Bootstrap 5, Bootstrap Icons
**Storage:** CSV files (`logs.csv`, `blacklist.txt`)
**Libraries used:** Flask, csv, os, collections, datetime (all built-in except Flask)

No AI, no Machine Learning, no external database — everything is procedural Python and rule-based logic.

## Folder Structure

```
SOC-Log-Analyzer/
│
├── app.py                     # Main Flask app and routes
├── analyzer.py                # Builds dashboard statistics
├── detector.py                # Rule-based detection logic
├── report.py                  # Incident report generation
├── utils.py                   # Shared helper functions
├── requirements.txt           # Python dependencies
├── logs.csv                   # 200 sample security log entries
├── blacklist.txt              # 20 known malicious IP addresses
│
├── templates/
│   ├── index.html              # Dashboard page
│   ├── alerts.html             # Alerts table page
│   └── report.html             # Incident report page
│
├── static/
│   └── style.css               # Dark SOC theme styling
│
├── reports/
│   └── incident_report.txt     # Auto-generated incident report
│
└── README.md
```

## Installation

1. Clone or download this project folder.
2. Open the folder in Visual Studio Code.
3. Create a virtual environment (optional but recommended):
   ```
   python -m venv venv
   venv\Scripts\activate      # Windows
   source venv/bin/activate   # macOS/Linux
   ```
4. Install the dependencies:
   ```
   pip install -r requirements.txt
   ```

## How To Run

```
python app.py
```

Then open your browser and go to:

```
http://127.0.0.1:5000
```

Navigate the sidebar to view the **Dashboard**, **Alerts**, and **Incident Report** pages. Click **Generate Report** at any time to re-run the detection rules and refresh `reports/incident_report.txt`.

## Screenshots

*(Add screenshots of the Dashboard, Alerts page, and Incident Report page here before submitting to your resume/portfolio.)*

## Future Enhancements

- Add a search/filter bar on the Alerts page
- Allow uploading a new `logs.csv` file directly from the dashboard
- Add a simple login page for analyst authentication
- Export incident reports as PDF
- Add a timeline/chart view of alerts over time
- Support real-time log ingestion instead of static CSV files

## Disclaimer

This project uses simulated log data for educational and demonstration purposes only. It is not connected to any live network or production system.
