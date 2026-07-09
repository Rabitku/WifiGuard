from checks.network_info import get_network_info
from checks.wifi_info import get_wifi_network_info
from checks.dns_info import get_dns_info
from checks.macos_firewall_info import get_firewall_status
from checks.vpn_info import get_vpn_status
from checks.gateway_info import get_default_gateway
from checks.sharing_info import get_sharing_services_status
from core.dns_classifier import classify_dns_servers
from core.risk_engine import calculate_risk


def build_check_results(
    network_info,
    wifi_info,
    dns_info,
    classified_dns_servers,
    firewall_status,
    vpn_status,
    gateway_info,
    sharing_services_status,
    risk_result
):
    check_results = [
        {
            "check_name": "Wi-Fi network",
            "status": wifi_info.get("status"),
            "message": wifi_info.get("message"),
            "raw_value": wifi_info
        },
        {
            "check_name": "Active network interfaces",
            "status": network_info.get("status"),
            "message": network_info.get("message"),
            "raw_value": network_info
        },
        {
            "check_name": "Default gateway",
            "status": gateway_info.get("status"),
            "message": gateway_info.get("message"),
            "raw_value": gateway_info
        },
        {
            "check_name": "DNS servers",
            "status": dns_info.get("status"),
            "message": dns_info.get("message"),
            "raw_value": {
                "servers": dns_info.get("servers", []),
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


def run_wifiguard_scan(network_context="unknown"):
    network_info = get_network_info()
    wifi_info = get_wifi_network_info()
    dns_info = get_dns_info()
    dns_servers = dns_info["servers"]
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
        gateway_info=gateway_info,
        network_context=network_context
    )
    check_results = build_check_results(
        network_info=network_info,
        wifi_info=wifi_info,
        dns_info=dns_info,
        classified_dns_servers=classified_dns_servers,
        firewall_status=firewall_status,
        vpn_status=vpn_status,
        gateway_info=gateway_info,
        sharing_services_status=sharing_services_status,
        risk_result=risk_result
    )

    return {
        "network_info": network_info,
        "wifi_info": wifi_info,
        "dns_info": dns_info,
        "classified_dns_servers": classified_dns_servers,
        "firewall_status": firewall_status,
        "vpn_status": vpn_status,
        "gateway_info": gateway_info,
        "sharing_services_status": sharing_services_status,
        "network_context": risk_result.get("network_context"),
        "risk_result": risk_result,
        "check_results": check_results
    }
