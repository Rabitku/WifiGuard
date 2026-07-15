import argparse

from cli_output import print_pruned_reports, print_scan_header, print_scan_result
from core.scan_runner import run_wifiguard_scan
from report_history import (
    prompt_to_clear_report_history,
    prompt_to_view_recent_reports,
    show_report_history,
)
from storage.database import prune_old_reports, save_report


def positive_int(value):
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("history limit must be a number")

    if number < 1:
        raise argparse.ArgumentTypeError("history limit must be 1 or greater")

    return number


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Run WiFiGuard local Wi-Fi risk checks."
    )
    command_group = parser.add_mutually_exclusive_group()
    command_group.add_argument(
        "--history",
        nargs="?",
        const=5,
        type=positive_int,
        metavar="LIMIT",
        help="show recent saved report summaries instead of running a scan"
    )
    command_group.add_argument(
        "--clear-history",
        action="store_true",
        help="delete all local saved reports after confirmation"
    )

    return parser.parse_args()


def prompt_for_network_context():
    try:
        answer = input("Are you using a public or shared Wi-Fi network? (y/n): ")
    except EOFError:
        return "unknown"

    answer = answer.strip().lower()

    if answer in ["y", "yes"]:
        return "public"

    if answer in ["n", "no"]:
        return "trusted"

    return "unknown"


def run_scan():
    print_scan_header()
    network_context = prompt_for_network_context()
    scan_result = run_wifiguard_scan(network_context=network_context)
    network_info = scan_result["network_info"]
    wifi_info = scan_result["wifi_info"]
    wifi_network_name = wifi_info["name"]
    risk_result = scan_result["risk_result"]
    check_results = scan_result["check_results"]

    report_id = save_report(
        device_name=network_info["hostname"],
        wifi_name=wifi_network_name,
        risk_result=risk_result,
        check_results=check_results
    )

    print_scan_result(scan_result, report_id)
    deleted_reports = prune_old_reports()
    print_pruned_reports(deleted_reports)
    prompt_to_view_recent_reports()


def main():
    args = parse_arguments()

    if args.history is not None:
        show_report_history(args.history)
        return

    if args.clear_history:
        prompt_to_clear_report_history()
        return

    run_scan()


if __name__ == "__main__":
    main()
