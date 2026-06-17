from checks.network_info import get_network_info
from core.risk_engine import calculate_basic_risk
from checks.wifi_info import get_wifi_network_name
from checks.dns_info import get_dns_servers
from core.dns_classifier import classify_dns_servers
from checks.macos_firewall_info import get_firewall_status

def main():
    print("WiFiGuard by RabitCodeKu")
    print("Know your connection. Reduce your risk. Privacy matters.")
    print("-" * 40)

    network_info = get_network_info()
    wifi_network_name = get_wifi_network_name()
    dns_servers = get_dns_servers()
    firewall_status = get_firewall_status()
    risk_result = calculate_basic_risk(network_info)
    classified_dns_servers = classify_dns_servers(dns_servers)

    print(f"\nDevice name: {network_info['hostname']}")
    print(f"\nConnected Wi-Fi network: {wifi_network_name}")
    print(f"\nFirewall status: {firewall_status['Status']}")
    print(f"Firewall message: {firewall_status['message']}")
    print("\nDNS servers:")

    if not classified_dns_servers:
     print("Unable to detect DNS servers.")
    else:
     for dns_server in classified_dns_servers:
        print(f"- {dns_server['server']}")
        print(f"  Classification: {dns_server['classification']}")
        print(f"  Provider: {dns_server['provider']}")
        print(f"  Notes: {dns_server['notes']}")

    print("\nActive network interfaces:")


    if not network_info["active_interfaces"]:
        print("No active network interfaces found.")
    else:
        for interface in network_info["active_interfaces"]:
            print(f"- {interface['interface']}: {interface['ip_address']}")
            
    

    print("\nRisk level:")
    print(risk_result["level"])
    print(risk_result["message"])


if __name__ == "__main__":
    main()