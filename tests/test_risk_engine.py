from core.risk_engine import calculate_risk


def make_network_info(active=True):
    if not active:
        return {
            "hostname": "Test-Mac.local",
            "active_interfaces": []
        }

    return {
        "hostname": "Test-Mac.local",
        "active_interfaces": [
            {
                "interface": "en0",
                "ip_address": "192.168.1.10"
            }
        ]
    }


def make_firewall_status(status="Enabled"):
    if status == "Enabled":
        return {
            "Status": "Enabled",
            "message": "Your firewall is active."
        }

    if status == "Disabled":
        return {
            "Status": "Disabled",
            "message": "Your firewall is not active. This may expose your system to potential threats"
        }

    return {
        "Status": "Unavailable",
        "message": "WiFiGuard could not verify the firewall status on this Mac."
    }


def make_vpn_status(status="Not detected"):
    return {
        "status": status,
        "message": "VPN routing was not confirmed."
    }


def make_private_dns_servers():
    return [
        {
            "server": "192.168.1.1",
            "classification": "Private/local DNS",
            "provider": "Local network",
            "notes": "This appears to be a private or local network DNS server."
        }
    ]


def make_gateway_info(detected=True):
    if detected:
        return {
            "gateway": "192.168.1.1",
            "interface": "en0",
            "status": "Detected",
            "message": "WiFiGuard detected the local gateway used for default network traffic."
        }

    return {
        "gateway": None,
        "interface": None,
        "status": "Not detected",
        "message": "The gateway check completed, but no default gateway was detected."
    }


def make_sharing_services(active=False):
    if active:
        return [
            {
                "service": "File Sharing",
                "status": "Active",
                "confidence": "Medium",
                "message": "The SMB file sharing service appears to be running."
            }
        ]

    return [
        {
            "service": "File Sharing",
            "status": "Not active",
            "confidence": "Medium",
            "message": "The SMB file sharing service does not appear to be running."
        }
    ]


def make_unavailable_sharing_services():
    return [
        {
            "service": "Remote Apple Events",
            "status": "Unavailable",
            "confidence": "Low",
            "message": "WiFiGuard could not verify Remote Apple Events status on this Mac."
        }
    ]


def calculate_baseline_risk(
    firewall_status=None,
    sharing_services=None,
    network_info=None,
    vpn_status=None,
    classified_dns_servers=None,
    gateway_info=None,
    network_context="trusted"
):
    return calculate_risk(
        network_info=network_info or make_network_info(),
        firewall_status=firewall_status or make_firewall_status("Enabled"),
        vpn_status=vpn_status or make_vpn_status(),
        classified_dns_servers=classified_dns_servers or make_private_dns_servers(),
        sharing_services=sharing_services or make_sharing_services(active=False),
        gateway_info=gateway_info or make_gateway_info(detected=True),
        network_context=network_context
    )


def text_contains(items, expected_text):
    combined_text = " ".join(items).lower()
    return expected_text.lower() in combined_text


def test_no_active_network_interface_returns_unknown_state():
    result = calculate_baseline_risk(
        network_info=make_network_info(active=False)
    )

    assert result["level"] == "Unknown"
    assert result["score"] is None
    assert text_contains(result["findings"], "could not detect an active network interface")
    assert text_contains(result["recommendations"], "connect to a network")


def test_firewall_enabled_is_recognised_without_enable_firewall_recommendation():
    result = calculate_baseline_risk(
        firewall_status={
            "Status": "Firewall is enabled",
            "message": "Your firewall is active."
        }
    )

    assert text_contains(result["findings"], "firewall is enabled")
    assert not text_contains(result["findings"], "firewall status could not be confirmed")
    assert not text_contains(result["recommendations"], "enable the macos firewall")


def test_safe_looking_trusted_network_can_remain_lower_risk():
    result = calculate_baseline_risk(network_context="trusted")

    assert result["level"] == "Lower risk"
    assert result["score"] == 5
    assert result["network_context"] == "trusted"
    assert text_contains(result["findings"], "marked as trusted")


def test_same_setup_marked_public_gets_higher_score():
    trusted_result = calculate_baseline_risk(network_context="trusted")
    public_result = calculate_baseline_risk(network_context="public")

    assert public_result["score"] > trusted_result["score"]
    assert public_result["level"] == "Medium caution"
    assert text_contains(public_result["findings"], "public or shared")
    assert text_contains(public_result["recommendations"], "trusted vpn")


def test_public_network_without_confirmed_vpn_does_not_get_tiny_score():
    result = calculate_baseline_risk(network_context="public")

    assert result["score"] == 30
    assert result["score"] > 5
    assert result["level"] == "Medium caution"
    assert text_contains(
        result["findings"],
        "vpn protection was not confirmed on a public or shared network"
    )


def test_default_network_context_is_unknown_and_less_cautious_than_public():
    unknown_result = calculate_risk(
        network_info=make_network_info(),
        firewall_status=make_firewall_status("Enabled"),
        vpn_status=make_vpn_status(),
        classified_dns_servers=make_private_dns_servers(),
        sharing_services=make_sharing_services(active=False),
        gateway_info=make_gateway_info(detected=True)
    )
    public_result = calculate_baseline_risk(network_context="public")

    assert unknown_result["network_context"] == "unknown"
    assert unknown_result["score"] < public_result["score"]
    assert text_contains(unknown_result["findings"], "network trust context was not specified")


def test_firewall_disabled_scores_higher_than_firewall_enabled():
    enabled_result = calculate_baseline_risk(
        firewall_status=make_firewall_status("Enabled")
    )
    disabled_result = calculate_baseline_risk(
        firewall_status=make_firewall_status("Disabled")
    )

    assert disabled_result["score"] > enabled_result["score"]
    assert text_contains(disabled_result["findings"], "firewall appears to be disabled")
    assert text_contains(disabled_result["recommendations"], "enable the macos firewall")


def test_unavailable_firewall_is_not_treated_like_disabled_firewall():
    enabled_result = calculate_baseline_risk(
        firewall_status=make_firewall_status("Enabled")
    )
    unavailable_result = calculate_baseline_risk(
        firewall_status={
            "Status": "Unavailable",
            "message": "WiFiGuard could not verify the firewall status on this Mac."
        }
    )
    disabled_result = calculate_baseline_risk(
        firewall_status=make_firewall_status("Disabled")
    )

    assert unavailable_result["score"] == enabled_result["score"]
    assert unavailable_result["score"] < disabled_result["score"]
    assert text_contains(unavailable_result["findings"], "could not verify the firewall")
    assert not text_contains(unavailable_result["recommendations"], "enable the macos firewall")


def test_active_sharing_service_increases_score_and_adds_recommendation():
    inactive_result = calculate_baseline_risk(
        sharing_services=make_sharing_services(active=False)
    )
    active_result = calculate_baseline_risk(
        sharing_services=make_sharing_services(active=True)
    )

    assert active_result["score"] > inactive_result["score"]
    assert text_contains(active_result["findings"], "file sharing")
    assert text_contains(active_result["recommendations"], "sharing services")
    assert text_contains(active_result["recommendations"], "turn off")


def test_unavailable_sharing_service_is_not_treated_as_active():
    inactive_result = calculate_baseline_risk(
        sharing_services=make_sharing_services(active=False)
    )
    unavailable_result = calculate_baseline_risk(
        sharing_services=make_unavailable_sharing_services()
    )

    assert unavailable_result["score"] == inactive_result["score"]
    assert text_contains(unavailable_result["findings"], "could not verify some sharing services")
    assert not text_contains(unavailable_result["recommendations"], "turn off sharing services")


def test_safer_baseline_returns_score_findings_and_recommendations():
    result = calculate_baseline_risk()

    assert isinstance(result["score"], int)
    assert 0 <= result["score"] <= 100
    assert result["level"] in ["Lower risk", "Medium caution", "Higher caution"]
    assert isinstance(result["findings"], list)
    assert result["findings"]
    assert isinstance(result["recommendations"], list)
    assert result["recommendations"]
