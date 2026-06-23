import subprocess


def get_firewall_status():
    try:
        result = subprocess.run(
            ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode != 0:
            return {
                "Status": "Unavailable",
                "message": "WiFiGuard could not verify the firewall status on this Mac."
            }

        output = result.stdout.strip().lower()

        if "enabled" in output:
            return {
                "Status": "Enabled",
                "message": "Your firewall is active."
            }

        if "disabled" in output:
            return {
                "Status": "Disabled",
                "message": "Your firewall is not active."
            }

        return {
            "Status": "Unavailable",
            "message": "WiFiGuard could not verify the firewall status on this Mac."
        }

    except Exception:
        return {
            "Status": "Check failed",
            "message": "WiFiGuard could not complete the firewall check."
        }
