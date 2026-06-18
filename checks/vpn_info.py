import psutil


VPN_INTERFACE_KEYWORDS = [
    "utun",
    "tun",
    "tap",
    "ppp",
    "ipsec",
    "wg",
    "wireguard",
    "tailscale",
    "proton",
    "nord",
    "mullvad",
    "openvpn"
]


def is_vpn_like_interface(interface_name):
    interface_name_lower = interface_name.lower()

    for keyword in VPN_INTERFACE_KEYWORDS:
        if keyword in interface_name_lower:
            return True

    return False


def get_vpn_status():
    interfaces = psutil.net_if_addrs()
    interface_stats = psutil.net_if_stats()

    vpn_like_interfaces = []

    for interface_name in interfaces:
        if not is_vpn_like_interface(interface_name):
            continue

        stats = interface_stats.get(interface_name)

        if stats and stats.isup:
            vpn_like_interfaces.append(interface_name)

    if vpn_like_interfaces:
        return {
            "status": "VPN-like interface detected",
            "detected_interfaces": vpn_like_interfaces,
            "message": "A VPN or tunnel-like network interface appears to be active. This does not guarantee that all traffic is routed through a VPN."
        }

    return {
        "status": "No VPN-like interface detected",
        "detected_interfaces": [],
        "message": "WiFiGuard did not detect an active VPN-like interface. Consider using a trusted VPN on public Wi-Fi."
    }