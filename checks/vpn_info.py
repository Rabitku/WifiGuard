import re
import subprocess
import psutil


TUNNEL_INTERFACE_PREFIXES = [
    "utun",
    "tun",
    "tap",
    "ppp",
    "wg"
]


def is_tunnel_interface(interface_name):
    interface_name = interface_name.lower()

    for prefix in TUNNEL_INTERFACE_PREFIXES:
        if interface_name.startswith(prefix):
            return True

    return False


def get_default_route_interface():
    try:
        result = subprocess.run(
            ["route", "-n", "get", "default"],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode != 0:
            return None

        for line in result.stdout.splitlines():
            line = line.strip()

            if line.startswith("interface:"):
                return line.replace("interface:", "").strip()

        return None

    except Exception:
        return None


def get_active_tunnel_interfaces():
    interfaces = psutil.net_if_addrs()
    interface_stats = psutil.net_if_stats()

    active_tunnel_interfaces = []

    for interface_name in interfaces:
        if not is_tunnel_interface(interface_name):
            continue

        stats = interface_stats.get(interface_name)

        if stats and stats.isup:
            active_tunnel_interfaces.append(interface_name)

    return active_tunnel_interfaces


def get_configured_vpn_services():
    """
    Uses macOS scutil to list configured VPN/network connection services.

    This may not show every third-party VPN app.
    """
    try:
        result = subprocess.run(
            ["scutil", "--nc", "list"],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode != 0:
            return []

        services = []

        for line in result.stdout.splitlines():
            line = line.strip()

            if not line:
                continue

            if line.startswith("Available network connection services"):
                continue

            name_match = re.search(r'"([^"]+)"', line)
            state_match = re.search(r"\(([^)]+)\)", line)

            service_name = name_match.group(1) if name_match else line
            listed_state = state_match.group(1) if state_match else "Unknown"

            services.append({
                "name": service_name,
                "listed_state": listed_state,
                "raw": line
            })

        return services

    except Exception:
        return []


def get_vpn_service_status(service_name):
    """
    Checks the status of a configured macOS VPN service by name.
    """
    try:
        result = subprocess.run(
            ["scutil", "--nc", "status", service_name],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode != 0:
            return "Unknown"

        for line in result.stdout.splitlines():
            line = line.strip()

            if line:
                return line

        return "Unknown"

    except Exception:
        return "Unknown"


def get_connected_vpn_services(configured_services):
    connected_services = []

    for service in configured_services:
        service_name = service["name"]
        status = get_vpn_service_status(service_name)

        service["status"] = status

        if status.lower().startswith("connected"):
            connected_services.append(service)

    return connected_services


def get_vpn_status():
    default_route_interface = get_default_route_interface()
    tunnel_interfaces = get_active_tunnel_interfaces()
    configured_vpn_services = get_configured_vpn_services()
    connected_vpn_services = get_connected_vpn_services(configured_vpn_services)

    evidence = []

    if default_route_interface:
        evidence.append(f"Default route interface: {default_route_interface}")
    else:
        evidence.append("Default route interface could not be determined.")

    if tunnel_interfaces:
        evidence.append(f"{len(tunnel_interfaces)} active tunnel-like interface(s) detected.")
    else:
        evidence.append("No active tunnel-like interfaces detected.")

    if connected_vpn_services:
        evidence.append("macOS reports one or more VPN services as connected.")
    elif configured_vpn_services:
        evidence.append("Configured macOS VPN services exist, but none appear connected.")
    else:
        evidence.append("No configured macOS VPN services were reported by scutil.")

    default_route_uses_tunnel = (
        default_route_interface is not None
        and is_tunnel_interface(default_route_interface)
    )

    if default_route_uses_tunnel and connected_vpn_services:
        return {
            "status": "Possible VPN active",
            "confidence": "High",
            "default_route_interface": default_route_interface,
            "tunnel_interfaces": tunnel_interfaces,
            "configured_vpn_services": configured_vpn_services,
            "connected_vpn_services": connected_vpn_services,
            "evidence": evidence,
            "message": "Your default internet route uses a tunnel interface and macOS reports a VPN service as connected. WiFiGuard still cannot guarantee the VPN provider or protection level."
        }

    if default_route_uses_tunnel:
        return {
            "status": "Possible VPN route detected",
            "confidence": "Medium",
            "default_route_interface": default_route_interface,
            "tunnel_interfaces": tunnel_interfaces,
            "configured_vpn_services": configured_vpn_services,
            "connected_vpn_services": connected_vpn_services,
            "evidence": evidence,
            "message": "Your default internet route appears to use a tunnel interface. This may indicate VPN routing, but WiFiGuard cannot confirm the VPN provider."
        }

    if connected_vpn_services:
        return {
            "status": "VPN service connected, route not confirmed",
            "confidence": "Medium",
            "default_route_interface": default_route_interface,
            "tunnel_interfaces": tunnel_interfaces,
            "configured_vpn_services": configured_vpn_services,
            "connected_vpn_services": connected_vpn_services,
            "evidence": evidence,
            "message": "macOS reports a VPN service as connected, but WiFiGuard did not confirm that the default internet route is using a tunnel interface. This may happen with split-tunnel VPNs."
        }

    if tunnel_interfaces:
        return {
            "status": "VPN route not confirmed",
            "confidence": "Low",
            "default_route_interface": default_route_interface,
            "tunnel_interfaces": tunnel_interfaces,
            "configured_vpn_services": configured_vpn_services,
            "connected_vpn_services": connected_vpn_services,
            "evidence": evidence,
            "message": "Tunnel-like interfaces are present, but this is common on macOS and does not prove that VPN protection is active."
        }

    return {
        "status": "No VPN evidence found",
        "confidence": "Low",
        "default_route_interface": default_route_interface,
        "tunnel_interfaces": tunnel_interfaces,
        "configured_vpn_services": configured_vpn_services,
        "connected_vpn_services": connected_vpn_services,
        "evidence": evidence,
        "message": "WiFiGuard did not detect local signs of VPN routing or connected macOS VPN services."
    }