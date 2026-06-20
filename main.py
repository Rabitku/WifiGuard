import argparse

from checks.network_info import get_network_info
from core.risk_engine import calculate_risk
from checks.wifi_info import get_wifi_network_name
from checks.dns_info import get_dns_servers
from core.dns_classifier import classify_dns_servers
from checks.macos_firewall_info import get_firewall_status
from checks.vpn_info import get_vpn_status
from core.ip_classifier import classify_ip_address
from checks.gateway_info import get_default_gateway
from checks.sharing_info import get_sharing_services_status
from report_history import (
    prompt_to_clear_report_history,
    prompt_to_view_recent_reports,
    show_report_history,
)
from storage.database import initialise_database, prune_old_reports, save_report


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


def build_check_results(
    network_info,
    wifi_network_name,
    dns_servers,
    classified_dns_servers,
    firewall_status,
    vpn_status,
    gateway_info,
    sharing_services_status,
    risk_result
):
    active_interfaces = network_info.get("active_interfaces", [])

    check_results = [
        {
            "check_name": "Wi-Fi network",
            "status": wifi_network_name,
            "message": "Detected Wi-Fi network name or macOS privacy fallback.",
            "raw_value": wifi_network_name
        },
        {
            "check_name": "Active network interfaces",
            "status": "Detected" if active_interfaces else "Not detected",
            "message": f"{len(active_interfaces)} active interface(s) found.",
            "raw_value": active_interfaces
        },
        {
            "check_name": "Default gateway",
            "status": gateway_info.get("status"),
            "message": gateway_info.get("message"),
            "raw_value": gateway_info
        },
        {
            "check_name": "DNS servers",
            "status": "Detected" if dns_servers else "Not detected",
            "message": f"{len(dns_servers)} DNS server(s) found.",
            "raw_value": {
                "servers": dns_servers,
                "classified_servers": classified_dns_servers
            }
        },
        {
            "check_name": "macOS firewall",
            "status": firewall_status.get("Status"),
            "message": firewall_status.get("message"),
            "raw_value": firewall_status
        },
        {
            "check_name": "VPN / tunnel routing",
            "status": vpn_status.get("status"),
            "message": vpn_status.get("message"),
            "raw_value": vpn_status
        },
        {
            "check_name": "Sharing services",
            "status": "Checked",
            "message": f"{len(sharing_services_status)} sharing service(s) checked.",
            "raw_value": sharing_services_status
        },
        {
            "check_name": "Risk engine",
            "status": risk_result.get("level"),
            "message": risk_result.get("summary"),
            "raw_value": risk_result
        }
    ]

    return check_results


def run_scan():
    print("WiFiGuard by RabitCodeKu")
    print("Know your connection. Reduce your risk. Privacy matters.")
    print("-" * 40)

    initialise_database()

    network_info = get_network_info()
    wifi_network_name = get_wifi_network_name()
    dns_servers = get_dns_servers()
    firewall_status = get_firewall_status()
    vpn_status = get_vpn_status()
    gateway_info = get_default_gateway()
    sharing_services_status = get_sharing_services_status()
    classified_dns_servers = classify_dns_servers(dns_servers)
    risk_result = calculate_risk(
        network_info=network_info,
        firewall_status=firewall_status,
        vpn_status=vpn_status,
        classified_dns_servers=classified_dns_servers,
        sharing_services=sharing_services_status,
        gateway_info=gateway_info
    )
    check_results = build_check_results(
        network_info=network_info,
        wifi_network_name=wifi_network_name,
        dns_servers=dns_servers,
        classified_dns_servers=classified_dns_servers,
        firewall_status=firewall_status,
        vpn_status=vpn_status,
        gateway_info=gateway_info,
        sharing_services_status=sharing_services_status,
        risk_result=risk_result
    )
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
    else:
        gateway_type = "Not detected"

    print(f"- Default gateway: {gateway_info['gateway'] or 'Not detected'}")
    print(f"- Gateway type: {gateway_type}")

    if gateway_info["interface"]:
        print(f"- Gateway interface: {gateway_info['interface']}")

    print(f"- Gateway details: {gateway_info['message']}")

    print("\nDNS servers:")
    if not classified_dns_servers:
        print("Unable to detect DNS servers.")
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
