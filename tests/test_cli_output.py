from cli_output import print_pruned_reports, print_scan_header, print_scan_result


def make_scan_result():
    return {
        "network_info": {
            "hostname": "Test-Mac.local",
            "active_interfaces": [
                {
                    "interface": "en0",
                    "ip_address": "192.168.1.10"
                }
            ]
        },
        "wifi_info": {
            "status": "Detected",
            "name": "Test Wi-Fi"
        },
        "dns_info": {
            "status": "Detected",
            "servers": ["192.168.1.1"],
            "message": "1 DNS server(s) detected."
        },
        "classified_active_interfaces": [
            {
                "interface": "en0",
                "ip_address": "192.168.1.10",
                "ip_classification": {
                    "classification": "Private/local address",
                    "notes": "This address is used inside a local network, not directly on the public internet."
                }
            }
        ],
        "classified_gateway": {
            "gateway": "192.168.1.1",
            "ip_classification": {
                "classification": "Private/local address",
                "notes": "This address is used inside a local network, not directly on the public internet."
            }
        },
        "classified_dns_servers": [
            {
                "server": "192.168.1.1",
                "classification": "Private/local DNS",
                "provider": "Local network",
                "notes": "This appears to be a private or local network DNS server."
            }
        ],
        "firewall_status": {
            "Status": "Enabled",
            "message": "Your firewall is active."
        },
        "vpn_status": {
            "status": "Not detected",
            "confidence": "Low",
            "default_route_interface": "en0",
            "tunnel_interfaces": [],
            "connected_vpn_services": [],
            "evidence": ["No active tunnel-like interfaces detected."],
            "message": "WiFiGuard did not detect local signs of VPN routing."
        },
        "gateway_info": {
            "gateway": "192.168.1.1",
            "interface": "en0",
            "status": "Detected",
            "message": "WiFiGuard detected the local gateway used for default network traffic."
        },
        "sharing_services_status": [
            {
                "service": "File Sharing",
                "status": "Not active"
            }
        ],
        "risk_result": {
            "level": "Lower risk",
            "score": 5,
            "summary": "Your device posture appears lower risk based on local checks.",
            "findings": ["Active network connection detected."],
            "recommendations": ["Continue using cautious browsing habits."]
        }
    }


def test_print_scan_header_displays_product_intro(capsys):
    print_scan_header()

    output = capsys.readouterr().out

    assert "WiFiGuard by RabitCodeKu" in output
    assert "Know your connection. Reduce your risk. Privacy matters." in output


def test_print_scan_result_displays_main_sections(capsys):
    print_scan_result(make_scan_result(), report_id=123)

    output = capsys.readouterr().out

    assert "Device:" in output
    assert "- Name: Test-Mac.local" in output
    assert "- Wi-Fi network: Test Wi-Fi" in output
    assert "- Local IP address: 192.168.1.10" in output
    assert "- Default gateway: 192.168.1.1" in output
    assert "- 192.168.1.1" in output
    assert "- Status: Enabled" in output
    assert "- File Sharing: Not active" in output
    assert "- Level: Lower risk" in output
    assert "Report saved locally with ID: 123" in output


def test_print_pruned_reports_only_outputs_when_reports_were_removed(capsys):
    print_pruned_reports(0)
    assert capsys.readouterr().out == ""

    print_pruned_reports(2)
    assert "Old reports cleaned up: 2 removed." in capsys.readouterr().out
