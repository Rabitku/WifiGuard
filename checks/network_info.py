import socket
import psutil


def get_network_info():
    hostname = socket.gethostname()

    try:
        interfaces = psutil.net_if_addrs()
    except Exception:
        return {
            "hostname": hostname,
            "status": "Check failed",
            "message": "WiFiGuard could not check active network interfaces.",
            "active_interfaces": []
        }

    active_interfaces = []

    for interface_name, addresses in interfaces.items():
        for address in addresses:
            if address.family == socket.AF_INET:
                ip_address = address.address

                if ip_address.startswith("127."):
                    continue

                if interface_name.startswith("lo"):
                    continue

                active_interfaces.append({
                    "interface": interface_name,
                    "ip_address": ip_address
                })

    if active_interfaces:
        status = "Detected"
        message = f"{len(active_interfaces)} active network interface(s) detected."
    else:
        status = "Not detected"
        message = "No active network interfaces were detected."

    return {
        "hostname": hostname,
        "status": status,
        "message": message,
        "active_interfaces": active_interfaces
    }
