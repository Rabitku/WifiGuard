from datetime import datetime

from storage.database import clear_all_reports, get_recent_reports, get_report_by_id


def format_report_date(created_at):
    if not created_at:
        return "Unknown"

    try:
        report_date = datetime.fromisoformat(created_at)
        return report_date.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return created_at


def format_score(risk_score):
    if risk_score is None:
        return "Unknown"

    return f"{risk_score}/100"


def show_report_history(limit=5):
    reports = get_recent_reports(limit)

    if not reports:
        print("No saved reports found.")
        return

    print("Recent WiFiGuard reports:")

    for report in reports:
        print(f"- ID: {report.get('id')}")
        print(f"  Date: {format_report_date(report.get('created_at'))}")
        print(f"  Device: {report.get('device_name') or 'Unknown'}")
        print(f"  Wi-Fi: {report.get('wifi_name') or 'Unknown'}")
        print(f"  Risk: {report.get('risk_level') or 'Unknown'}")
        print(f"  Score: {format_score(report.get('risk_score'))}")
        print(f"  Summary: {report.get('summary') or 'No summary available.'}")


def show_recent_report_list(reports):
    print("Recent WiFiGuard reports:")

    for list_number, report in enumerate(reports, start=1):
        report_id = report.get("id")
        report_date = format_report_date(report.get("created_at"))
        risk_level = report.get("risk_level") or "Unknown"
        score = format_score(report.get("risk_score"))

        print(
            f"{list_number}. ID: {report_id} | "
            f"Date: {report_date} | "
            f"Risk: {risk_level} | "
            f"Score: {score}"
        )


def show_report_details(report):
    print("\nReport details:")
    print(f"ID: {report.get('id')}")
    print(f"Date: {format_report_date(report.get('created_at'))}")
    print(f"Device: {report.get('device_name') or 'Unknown'}")
    print(f"Wi-Fi: {report.get('wifi_name') or 'Unknown'}")
    print(f"Risk: {report.get('risk_level') or 'Unknown'}")
    print(f"Score: {format_score(report.get('risk_score'))}")
    print(f"Summary: {report.get('summary') or 'No summary available.'}")

    print("\nSaved check results:")

    check_results = report.get("check_results", [])

    if not check_results:
        print("No saved check results are available for this report.")
        return

    for check_result in check_results:
        check_name = check_result.get("check_name") or "Unknown check"
        status = check_result.get("status") or "Unknown"
        message = check_result.get("message") or "No details available."

        print(f"- {check_name}: {status}")
        print(f"  Details: {message}")


def prompt_to_view_recent_reports(limit=5):
    try:
        answer = input("\nWould you like to view recent reports? (y/n): ")
    except EOFError:
        return

    answer = answer.strip().lower()

    if answer not in ["y", "yes"]:
        return

    reports = get_recent_reports(limit)

    if not reports:
        print("No saved reports found.")
        return

    print()
    show_recent_report_list(reports)

    try:
        selection = input(
            "\nEnter a report number to view details, or press Enter to skip: "
        )
    except EOFError:
        return

    selection = selection.strip()

    if not selection:
        return

    try:
        selected_number = int(selection)
    except ValueError:
        print("Invalid selection.")
        return

    if selected_number < 1 or selected_number > len(reports):
        print("Invalid selection.")
        return

    selected_report = reports[selected_number - 1]
    report = get_report_by_id(selected_report["id"])

    if report is None:
        print("Invalid selection.")
        return

    show_report_details(report)


def prompt_to_clear_report_history():
    print("This will permanently delete all local WiFiGuard reports.")

    try:
        confirmation = input("Type DELETE to continue: ")
    except EOFError:
        print("Report deletion cancelled.")
        return

    if confirmation != "DELETE":
        print("Report deletion cancelled.")
        return

    clear_all_reports()
    print("Local report history cleared.")
