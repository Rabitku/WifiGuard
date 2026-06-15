from checks.network_info import get_network_info
from core.risk_engine import calculate_basic_risk


def main():
    print("WiFiGuard")
    print("Know your connection. Reduce your risk. Privacy matters.")
    print("-" * 40)

    network_info = get_network_info()
    risk_result = calculate_basic_risk(network_info)

    print(f"Device name: {network_info['hostname']}")

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