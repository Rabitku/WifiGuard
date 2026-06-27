import argparse

from core.ip_classifier import classify_ip_address
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


def run_scan():
    print("WiFiGuard by RabitCodeKu")
    print("Know your connection. Reduce your risk. Privacy matters.")
    print("-" * 40)

    scan_result = run_wifiguard_scan()
    network_info = scan_result["network_info"]
    wifi_info = scan_result["wifi_info"]
    wifi_network_name = wifi_info["name"]
    dns_info = scan_result["dns_info"]
    firewall_status = scan_result["firewall_status"]
    vpn_status = scan_result["vpn_status"]
    gateway_info = scan_result["gateway_info"]
    sharing_services_status = scan_result["sharing_services_status"]
    classified_dns_servers = scan_result["classified_dns_servers"]
    risk_result = scan_result["risk_result"]
    check_results = scan_result["check_results"]

    report_id = save_report(
        device_name=network_info["hostname"],
        wifi_name=wifi_network_name,
        risk_result=risk_result,
        check_results=check_results
    )

    print("\nDevice:")
    print(f"- Name: {network_info['hostname']}")

    print("\nConnection:")
    print(f"- Wi-Fi network: {wifi_network_name}")
    print(f"- Wi-Fi status: {wifi_info['status']}")

    print("\nConnection details:")

    if not network_info["active_interfaces"]:
        print("- Active interface: Not detected")
        print("- Local IP address: Not detected")
        print("- IP type: Unknown")
        print("- IP notes: No active interface was available to classify.")
    else:
        primary_interface = network_info["active_interfaces"][0]
        ip_info = classify_ip_address(primary_interface["ip_address"])

        print(f"- Active interface: {primary_interface['interface']}")
        print(f"- Local IP address: {primary_interface['ip_address']}")
        print(f"- IP type: {ip_info['classification']}")
        print(f"- IP notes: {ip_info['notes']}")

    print(f"- Gateway status: {gateway_info['status']}")

    if gateway_info["gateway"]:
        gateway_ip_info = classify_ip_address(gateway_info["gateway"])
        gateway_type = gateway_ip_info["classification"]
        gateway_value = gateway_info["gateway"]
    else:
        gateway_value = gateway_info["status"]
        gateway_type = gateway_info["status"]

    print(f"- Default gateway: {gateway_value}")
    print(f"- Gateway type: {gateway_type}")

    if gateway_info["interface"]:
        print(f"- Gateway interface: {gateway_info['interface']}")

    print(f"- Gateway details: {gateway_info['message']}")

    print("\nDNS servers:")
    if not classified_dns_servers:
        print(f"- Status: {dns_info['status']}")
        print(f"- Details: {dns_info['message']}")
    else:
        for dns_server in classified_dns_servers:
            print(f"- {dns_server['server']}")
            print(f"  Classification: {dns_server['classification']}")
            print(f"  Provider: {dns_server['provider']}")
            print(f"  Notes: {dns_server['notes']}")

    print("\nFirewall:")
    print(f"- Status: {firewall_status['Status']}")
    print(f"- Details: {firewall_status['message']}")
    
    print("\nVPN / Tunnel routing:")
    print(f"- Status: {vpn_status['status']}")
    print(f"- Confidence: {vpn_status['confidence']}")
    print(f"- Default route interface: {vpn_status['default_route_interface']}")

    print(f"- Tunnel interfaces detected: {len(vpn_status['tunnel_interfaces'])}")

    if vpn_status["connected_vpn_services"]:
        print("- Connected macOS VPN services:")
        for service in vpn_status["connected_vpn_services"]:
            print(f"  - {service['name']} ({service['status']})")

    print(f"- Details: {vpn_status['message']}")

    print("- Evidence:")
    for item in vpn_status["evidence"]:
        print(f"  - {item}")
        
    print("\nSharing services:")

    for service in sharing_services_status:
        print(f"- {service['service']}: {service['status']}")
        
    print("\nRisk level:")
    print(f"- Level: {risk_result['level']}")

    if risk_result["score"] is not None:
        print(f"- Score: {risk_result['score']}/100")

    print(f"- Summary: {risk_result['summary']}")

    print("\nMain findings:")
    for finding in risk_result["findings"]:
        print(f"- {finding}")

    print("\nRecommendations:")
    for recommendation in risk_result["recommendations"]:
        print(f"- {recommendation}")

    print(f"\nReport saved locally with ID: {report_id}")

    deleted_reports = prune_old_reports()

    if deleted_reports > 0:
        print(f"Old reports cleaned up: {deleted_reports} removed.")

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
