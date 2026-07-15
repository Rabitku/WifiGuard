from core.ip_classifier import classify_ip_address


def print_scan_header():
    print("WiFiGuard by RabitCodeKu")
    print("Know your connection. Reduce your risk. Privacy matters.")
    print("-" * 40)


def print_connection_details(network_info, gateway_info):
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


def print_dns_servers(dns_info, classified_dns_servers):
    print("\nDNS servers:")

    if not classified_dns_servers:
        print(f"- Status: {dns_info['status']}")
        print(f"- Details: {dns_info['message']}")
        return

    for dns_server in classified_dns_servers:
        print(f"- {dns_server['server']}")
        print(f"  Classification: {dns_server['classification']}")
        print(f"  Provider: {dns_server['provider']}")
        print(f"  Notes: {dns_server['notes']}")


def print_vpn_status(vpn_status):
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


def print_risk_result(risk_result):
    print("\nRisk level:")
    print(f"- Level: {risk_result['level']}")

    if risk_result["score"] is not None:
        print(f"- Score: {risk_result['score']}/100")

    print(f"- Summary: {risk_result['summary']}")
    print("- Note: WiFiGuard checks local device and connection indicators; it cannot guarantee that a network is safe.")

    print("\nMain findings:")
    for finding in risk_result["findings"]:
        print(f"- {finding}")

    print("\nRecommendations:")
    for recommendation in risk_result["recommendations"]:
        print(f"- {recommendation}")


def print_scan_result(scan_result, report_id):
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

    print("\nDevice:")
    print(f"- Name: {network_info['hostname']}")

    print("\nConnection:")
    print(f"- Wi-Fi network: {wifi_network_name}")
    print(f"- Wi-Fi status: {wifi_info['status']}")

    print_connection_details(network_info, gateway_info)
    print_dns_servers(dns_info, classified_dns_servers)

    print("\nFirewall:")
    print(f"- Status: {firewall_status['Status']}")
    print(f"- Details: {firewall_status['message']}")

    print_vpn_status(vpn_status)

    print("\nSharing services:")
    for service in sharing_services_status:
        print(f"- {service['service']}: {service['status']}")

    print_risk_result(risk_result)
    print(f"\nReport saved locally with ID: {report_id}")


def print_pruned_reports(deleted_reports):
    if deleted_reports > 0:
        print(f"Old reports cleaned up: {deleted_reports} removed.")
