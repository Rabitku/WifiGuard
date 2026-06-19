from datetime import datetime

from storage.database import get_recent_reports


def format_report_date(created_at):
    if not created_at:
        return "Unknown"

    try:
        report_date = datetime.fromisoformat(created_at)
        return report_date.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return created_at


def show_report_history(limit=5):
    reports = get_recent_reports(limit)

    if not reports:
        print("No saved reports found.")
        return

    print("Recent WiFiGuard reports:")

    for report in reports:
        risk_score = report.get("risk_score")

        if risk_score is None:
            score_text = "Unknown"
        else:
            score_text = f"{risk_score}/100"

        print(f"- ID: {report.get('id')}")
        print(f"  Date: {format_report_date(report.get('created_at'))}")
        print(f"  Device: {report.get('device_name') or 'Unknown'}")
        print(f"  Wi-Fi: {report.get('wifi_name') or 'Unknown'}")
        print(f"  Risk: {report.get('risk_level') or 'Unknown'}")
        print(f"  Score: {score_text}")
        print(f"  Summary: {report.get('summary') or 'No summary available.'}")
