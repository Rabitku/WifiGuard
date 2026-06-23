import subprocess


def get_wifi_interface():
    try:
        result = subprocess.run(
            ["networksetup", "-listallhardwareports"],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode != 0:
            return None

        current_port = None

        for line in result.stdout.splitlines():
            line = line.strip()

            if line.startswith("Hardware Port:"):
                current_port = line.replace("Hardware Port:", "").strip()

            elif current_port == "Wi-Fi" and line.startswith("Device:"):
                return line.replace("Device:", "").strip()

        return None

    except Exception:
        return None


def get_wifi_name_from_networksetup(wifi_interface):
    try:
        result = subprocess.run(
            ["networksetup", "-getairportnetwork", wifi_interface],
            capture_output=True,
            text=True,
            timeout=5
        )

        output = result.stdout.strip()

        if "Current Wi-Fi Network:" in output:
            ssid = output.replace("Current Wi-Fi Network:", "").strip()

            if ssid == "<redacted>":
                return "Hidden by macOS privacy settings"

            return ssid

        return None

    except Exception:
        return None


def get_wifi_name_from_ipconfig(wifi_interface):
    try:
        result = subprocess.run(
            ["ipconfig", "getsummary", wifi_interface],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode != 0:
            return None

        for line in result.stdout.splitlines():
            line = line.strip()

            if line.startswith("SSID :"):
                ssid = line.replace("SSID :", "").strip()

                if ssid == "<redacted>":
                    return "Hidden by macOS privacy settings"

                return ssid

        return None

    except Exception:
        return None


def get_wifi_network_name():
    wifi_info = get_wifi_network_info()
    return wifi_info["name"]


def get_wifi_network_info():
    wifi_interface = get_wifi_interface()

    if wifi_interface is None:
        return {
            "status": "Unavailable",
            "name": "Unavailable",
            "interface": None,
            "message": "WiFiGuard could not verify the Wi-Fi interface on this Mac."
        }

    wifi_name = get_wifi_name_from_networksetup(wifi_interface)

    if wifi_name:
        return {
            "status": "Detected",
            "name": wifi_name,
            "interface": wifi_interface,
            "message": "WiFiGuard detected the current Wi-Fi network name."
        }

    wifi_name = get_wifi_name_from_ipconfig(wifi_interface)

    if wifi_name:
        return {
            "status": "Detected",
            "name": wifi_name,
            "interface": wifi_interface,
            "message": "WiFiGuard detected the current Wi-Fi network name."
        }

    return {
        "status": "Unavailable",
        "name": "Unavailable",
        "interface": wifi_interface,
        "message": "WiFiGuard could not verify the Wi-Fi network name on this Mac."
    }
