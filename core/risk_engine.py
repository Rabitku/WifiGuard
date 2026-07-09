def normalise_status(value):
    return str(value or "").strip().lower()


def is_unavailable_or_failed(status):
    status = normalise_status(status)
    return status in ["unavailable", "check failed"]


def normalise_network_context(network_context):
    network_context = normalise_status(network_context)

    if network_context in ["trusted", "public", "unknown"]:
        return network_context

    return "unknown"


def calculate_risk(
    network_info,
    firewall_status,
    vpn_status,
    classified_dns_servers,
    sharing_services,
    gateway_info,
    network_context="unknown"
):
    score = 0
    findings = []
    recommendations = []
    network_context = normalise_network_context(network_context)

    # Network presence
    active_interfaces = network_info.get("active_interfaces", [])

    if not active_interfaces:
        return {
            "level": "Unknown",
            "score": None,
            "summary": "No active network connection was detected.",
            "network_context": network_context,
            "findings": ["WiFiGuard could not detect an active network interface."],
            "recommendations": ["Connect to a network before running WiFiGuard again."]
        }

    findings.append("Active network connection detected.")

    # Network trust context
    if network_context == "public":
        score += 15
        findings.append("This network was marked as public or shared.")
        recommendations.append(
            "Avoid sensitive activity on public Wi-Fi unless using a trusted VPN."
        )
    elif network_context == "unknown":
        score += 5
        findings.append("Network trust context was not specified.")
        recommendations.append(
            "Treat unfamiliar Wi-Fi as shared unless you trust the network."
        )
    else:
        findings.append("This network was marked as trusted.")

    # Gateway check
    gateway_status = normalise_status(gateway_info.get("status"))

    if gateway_info.get("gateway") or gateway_status == "detected":
        findings.append("Default gateway detected.")

    elif gateway_status == "not detected":
        score += 15
        findings.append("Default gateway could not be detected.")
        recommendations.append("Check whether the network connection is fully established.")

    elif is_unavailable_or_failed(gateway_status):
        findings.append("WiFiGuard could not verify the default gateway, so its status is unknown.")

    else:
        findings.append("Default gateway status could not be confirmed.")

    # Firewall check
    firewall_text = normalise_status(
        firewall_status.get("Status", firewall_status.get("status", ""))
    )

    if "enabled" in firewall_text:
        findings.append("Firewall is enabled.")

    elif "disabled" in firewall_text:
        score += 30
        findings.append("Firewall appears to be disabled.")
        recommendations.append("Enable the macOS firewall before using shared or public Wi-Fi.")

    elif is_unavailable_or_failed(firewall_text):
        findings.append("WiFiGuard could not verify the firewall, so its status is unknown.")

    else:
        findings.append("Firewall status could not be confirmed.")

    # VPN / tunnel routing check
    vpn_text = normalise_status(vpn_status.get("status"))

    if vpn_text == "detected" or "possible vpn active" in vpn_text or "possible vpn route detected" in vpn_text:
        findings.append("VPN or tunnel routing evidence detected.")

    elif vpn_text == "not detected" or "not confirmed" in vpn_text or "no vpn" in vpn_text:
        if network_context == "public":
            score += 15
            findings.append(
                "VPN protection was not confirmed on a public or shared network."
            )
            recommendations.append(
                "Use a trusted VPN before sensitive activity on public or shared Wi-Fi."
            )
        else:
            score += 5
            findings.append("VPN route was not confirmed.")
            recommendations.append("Consider using a trusted VPN when using shared or public Wi-Fi.")

    elif is_unavailable_or_failed(vpn_text):
        findings.append("WiFiGuard could not verify VPN routing, so its status is unknown.")

    else:
        findings.append("VPN status could not be clearly determined.")

    # DNS classification
    if not classified_dns_servers:
        findings.append("DNS servers were not detected or could not be verified.")
        recommendations.append("Check network settings if browsing or name resolution is not working.")
    else:
        dns_classes = [
            dns_server.get("classification", "")
            for dns_server in classified_dns_servers
        ]

        if any("Invalid" in dns_class for dns_class in dns_classes):
            score += 15
            findings.append("One or more DNS values looked invalid or unsupported.")
            recommendations.append("Review DNS settings if connectivity seems unreliable.")

        elif any("Network-provided or unknown public DNS" in dns_class for dns_class in dns_classes):
            findings.append("DNS is network-provided or unknown public DNS.")
            recommendations.append("Unknown DNS is not automatically unsafe, but be cautious on public Wi-Fi.")

        elif any("Known public DNS" in dns_class for dns_class in dns_classes):
            findings.append("Known public DNS provider detected.")

        elif any("Private/local DNS" in dns_class for dns_class in dns_classes):
            findings.append("Private/local DNS detected.")

        else:
            findings.append("DNS servers detected.")

    # Sharing services
    enabled_or_active_services = []
    unavailable_services = []

    for service in sharing_services:
        status = normalise_status(service.get("status"))

        if status in ["enabled", "active"]:
            enabled_or_active_services.append(service.get("service", "Unknown service"))

        elif status in ["unavailable", "check failed"]:
            unavailable_services.append(service.get("service", "Unknown service"))

    if enabled_or_active_services:
        score += 25
        findings.append(
            "Some sharing services appear enabled or active: "
            + ", ".join(enabled_or_active_services)
            + "."
        )
        recommendations.append("Turn off sharing services you do not need when using public Wi-Fi.")
    elif unavailable_services:
        findings.append(
            "WiFiGuard could not verify some sharing services: "
            + ", ".join(unavailable_services)
            + "."
        )
    else:
        findings.append("No clearly active sharing services detected.")

    # Clamp score to 0-100
    score = max(0, min(score, 100))

    if score <= 20:
        level = "Lower risk"
        summary = "Your device posture appears lower risk based on local checks, but WiFiGuard cannot guarantee that the network is safe."
    elif score <= 50:
        level = "Medium caution"
        summary = "Some recommended protections are missing or could not be confirmed."
    else:
        level = "Higher caution"
        summary = "Several risk factors were detected. Review the recommendations before using sensitive services."

    if not recommendations:
        recommendations.append("Continue using cautious browsing habits on shared or public Wi-Fi.")

    return {
        "level": level,
        "score": score,
        "summary": summary,
        "network_context": network_context,
        "findings": findings,
        "recommendations": recommendations
    }
    
