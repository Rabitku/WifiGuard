from checks.network_info import get_network_info
from core.risk_engine import calculate_basic_risk
from checks.wifi_info import get_wifi_network_name
from checks.dns_info import get_dns_servers
from core.dns_classifier import classify_dns_servers
from checks.macos_firewall_info import get_firewall_status
from checks.vpn_info import get_vpn_status

def main():
    print("WiFiGuard by RabitCodeKu")
    print("Know your connection. Reduce your risk. Privacy matters.")
    print("-" * 40)

    network_info = get_network_info()
    wifi_network_name = get_wifi_network_name()
    dns_servers = get_dns_servers()
    firewall_status = get_firewall_status()
    vpn_status = get_vpn_status()
    risk_result = calculate_basic_risk(network_info)
    classified_dns_servers = classify_dns_servers(dns_servers)

    print("\nDevice:")
    print(f"- Name: {network_info['hostname']}")

    print("\nConnection:")
    print(f"- Wi-Fi network: {wifi_network_name}")

    print("\nActive network interfaces:")
    if not network_info["active_interfaces"]:
        print("No active network interfaces found.")
    else:
        for interface in network_info["active_interfaces"]:
            print(f"- {interface['interface']}: {interface['ip_address']}")

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
    
if __name__ == "__main__":
    main()
