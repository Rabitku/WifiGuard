from checks.network_info import get_network_info
from core.risk_engine import calculate_basic_risk
from checks.wifi_info import get_wifi_network_name
from checks.dns_info import get_dns_servers

def main():
    print("WiFiGuard by RabitCodeKu")
    print("Know your connection. Reduce your risk. Privacy matters.")
    print("-" * 40)

    network_info = get_network_info()
    wifi_network_name = get_wifi_network_name()
    dns_servers = get_dns_servers()
    risk_result = calculate_basic_risk(network_info)

    print(f"\nDevice name: {network_info['hostname']}")
    print(f"\nConnected Wi-Fi network: {wifi_network_name}")
    print(f"\nDNS servers:")
    if not dns_servers:
        print("No DNS servers found.")
    else:
        for dns_server in dns_servers:
            print(f"- {dns_server}")

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