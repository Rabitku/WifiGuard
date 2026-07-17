import argparse

import main
from core import scan_runner
from storage import database


def install_mock_scan_dependencies(monkeypatch):
    network_info = {
        "hostname": "Test-Mac.local",
        "status": "Detected",
        "message": "1 active network interface(s) detected.",
        "active_interfaces": [
            {
                "interface": "en0",
                "ip_address": "192.168.1.10"
            }
        ]
    }
    wifi_info = {
        "status": "Detected",
        "name": "Test Wi-Fi",
        "interface": "en0",
        "message": "WiFiGuard detected the current Wi-Fi network name."
    }
    dns_info = {
        "status": "Detected",
        "servers": ["192.168.1.1"],
        "message": "1 DNS server(s) detected."
    }
    classified_dns_servers = [
        {
            "server": "192.168.1.1",
            "classification": "Private/local DNS",
            "provider": "Local network",
            "notes": "This appears to be a private or local network DNS server."
        }
    ]
    firewall_status = {
        "Status": "Enabled",
        "message": "Your firewall is active."
    }
    vpn_status = {
        "status": "Not detected",
        "confidence": "Low",
        "default_route_interface": "en0",
        "tunnel_interfaces": [],
        "configured_vpn_services": [],
        "connected_vpn_services": [],
        "evidence": ["No active tunnel-like interfaces detected."],
        "message": "WiFiGuard did not detect local signs of VPN routing."
    }
    gateway_info = {
        "gateway": "192.168.1.1",
        "interface": "en0",
        "status": "Detected",
        "message": "WiFiGuard detected the local gateway used for default network traffic."
    }
    sharing_services_status = [
        {
            "service": "File Sharing",
            "status": "Not active",
            "confidence": "Medium",
            "message": "The SMB file sharing service does not appear to be running."
        }
    ]
    risk_result = {
        "level": "Lower risk",
        "score": 5,
        "summary": "Your current setup appears lower risk based on local checks.",
        "findings": ["Active network connection detected."],
        "recommendations": ["Continue using cautious browsing habits."]
    }
    calls = {}

    def classify_dns_servers(dns_servers):
        calls["dns_servers"] = dns_servers
        return classified_dns_servers

    def calculate_risk(**kwargs):
        calls["risk_kwargs"] = kwargs
        result = dict(risk_result)
        result["network_context"] = kwargs.get("network_context", "unknown")
        return result

    monkeypatch.setattr(scan_runner, "get_network_info", lambda: network_info)
    monkeypatch.setattr(scan_runner, "get_wifi_network_info", lambda: wifi_info)
    monkeypatch.setattr(scan_runner, "get_dns_info", lambda: dns_info)
    monkeypatch.setattr(scan_runner, "get_firewall_status", lambda: firewall_status)
    monkeypatch.setattr(scan_runner, "get_vpn_status", lambda: vpn_status)
    monkeypatch.setattr(scan_runner, "get_default_gateway", lambda: gateway_info)
    monkeypatch.setattr(
        scan_runner,
        "get_sharing_services_status",
        lambda: sharing_services_status
    )
    monkeypatch.setattr(scan_runner, "classify_dns_servers", classify_dns_servers)
    monkeypatch.setattr(scan_runner, "calculate_risk", calculate_risk)

    return {
        "network_info": network_info,
        "wifi_info": wifi_info,
        "dns_info": dns_info,
        "classified_dns_servers": classified_dns_servers,
        "firewall_status": firewall_status,
        "vpn_status": vpn_status,
        "gateway_info": gateway_info,
        "sharing_services_status": sharing_services_status,
        "risk_result": risk_result,
        "calls": calls
    }


def test_run_wifiguard_scan_returns_expected_result_keys(monkeypatch):
    install_mock_scan_dependencies(monkeypatch)

    result = scan_runner.run_wifiguard_scan()

    assert set(result.keys()) == {
        "network_info",
        "wifi_info",
        "dns_info",
        "classified_active_interfaces",
        "classified_gateway",
        "classified_dns_servers",
        "firewall_status",
        "vpn_status",
        "gateway_info",
        "sharing_services_status",
        "network_context",
        "risk_result",
        "check_results"
    }


def test_run_wifiguard_scan_returns_report_ready_check_results(monkeypatch):
    expected = install_mock_scan_dependencies(monkeypatch)

    result = scan_runner.run_wifiguard_scan()
    check_results = result["check_results"]

    assert [check["check_name"] for check in check_results] == [
        "Wi-Fi network",
        "Active network interfaces",
        "Default gateway",
        "DNS servers",
        "macOS firewall",
        "VPN / tunnel routing",
        "Sharing services",
        "Risk engine"
    ]
    assert check_results[0]["status"] == "Detected"
    assert check_results[0]["raw_value"] == expected["wifi_info"]
    assert check_results[3]["raw_value"] == {
        "servers": ["192.168.1.1"],
        "classified_servers": expected["classified_dns_servers"]
    }
    assert check_results[-1]["status"] == "Lower risk"
    assert check_results[-1]["raw_value"]["level"] == expected["risk_result"]["level"]
    assert check_results[-1]["raw_value"]["network_context"] == "unknown"


def test_run_wifiguard_scan_returns_classified_ip_data(monkeypatch):
    install_mock_scan_dependencies(monkeypatch)

    result = scan_runner.run_wifiguard_scan()

    assert result["classified_active_interfaces"] == [
        {
            "interface": "en0",
            "ip_address": "192.168.1.10",
            "ip_classification": {
                "classification": "Private/local address",
                "notes": "This address is used inside a local network, not directly on the public internet."
            }
        }
    ]
    assert result["classified_gateway"] == {
        "gateway": "192.168.1.1",
        "ip_classification": {
            "classification": "Private/local address",
            "notes": "This address is used inside a local network, not directly on the public internet."
        }
    }


def test_run_wifiguard_scan_includes_risk_result(monkeypatch):
    expected = install_mock_scan_dependencies(monkeypatch)

    result = scan_runner.run_wifiguard_scan(network_context="public")

    assert result["network_context"] == "public"
    assert result["risk_result"]["level"] == expected["risk_result"]["level"]
    assert result["risk_result"]["network_context"] == "public"
    assert expected["calls"]["dns_servers"] == ["192.168.1.1"]
    assert expected["calls"]["risk_kwargs"] == {
        "network_info": expected["network_info"],
        "firewall_status": expected["firewall_status"],
        "vpn_status": expected["vpn_status"],
        "classified_dns_servers": expected["classified_dns_servers"],
        "sharing_services": expected["sharing_services_status"],
        "gateway_info": expected["gateway_info"],
        "network_context": "public"
    }


def test_run_wifiguard_scan_does_not_create_or_save_reports(monkeypatch, tmp_path):
    install_mock_scan_dependencies(monkeypatch)
    database_path = tmp_path / "wifiguard.db"
    monkeypatch.setattr(database, "DATABASE_PATH", database_path)

    scan_runner.run_wifiguard_scan()

    assert not database_path.exists()


def test_history_command_does_not_run_scan(monkeypatch):
    calls = {}

    monkeypatch.setattr(
        main,
        "parse_arguments",
        lambda: argparse.Namespace(history=5, clear_history=False)
    )
    monkeypatch.setattr(
        main,
        "run_wifiguard_scan",
        lambda: (_ for _ in ()).throw(AssertionError("scan should not run"))
    )
    monkeypatch.setattr(
        main,
        "show_report_history",
        lambda limit: calls.setdefault("history_limit", limit)
    )

    main.main()

    assert calls == {"history_limit": 5}


def test_clear_history_command_does_not_run_scan(monkeypatch):
    calls = {}

    monkeypatch.setattr(
        main,
        "parse_arguments",
        lambda: argparse.Namespace(history=None, clear_history=True)
    )
    monkeypatch.setattr(
        main,
        "run_wifiguard_scan",
        lambda: (_ for _ in ()).throw(AssertionError("scan should not run"))
    )
    monkeypatch.setattr(
        main,
        "prompt_to_clear_report_history",
        lambda: calls.setdefault("clear_history", True)
    )

    main.main()

    assert calls == {"clear_history": True}


def test_network_context_prompt_maps_answers(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda prompt: "yes")
    assert main.prompt_for_network_context() == "public"

    monkeypatch.setattr("builtins.input", lambda prompt: "n")
    assert main.prompt_for_network_context() == "trusted"

    monkeypatch.setattr("builtins.input", lambda prompt: "")
    assert main.prompt_for_network_context() == "unknown"
