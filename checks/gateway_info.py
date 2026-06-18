import subprocess


def get_default_gateway():
    try:
        result = subprocess.run(
            ["route", "-n", "get", "default"],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode != 0:
            return {
                "gateway": None,
                "interface": None,
                "status": "Unable to detect default gateway",
                "message": "WiFiGuard could not determine the default gateway."
            }

        gateway = None
        interface = None

        for line in result.stdout.splitlines():
            line = line.strip()

            if line.startswith("gateway:"):
                gateway = line.replace("gateway:", "").strip()

            if line.startswith("interface:"):
                interface = line.replace("interface:", "").strip()

        if gateway or interface:
            return {
                "gateway": gateway,
                "interface": interface,
                "status": "Default gateway detected",
                "message": "WiFiGuard detected the local gateway used for default network traffic."
            }

        return {
            "gateway": None,
            "interface": None,
            "status": "Unable to detect default gateway",
            "message": "The default route command ran, but no gateway information was found."
        }

    except Exception:
        return {
            "gateway": None,
            "interface": None,
            "status": "Gateway check failed",
            "message": "WiFiGuard could not complete the gateway check."
        }