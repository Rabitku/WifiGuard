import subprocess

def get_wifi_network_name():
    try:
        result = subprocess.run(
            [
                "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport",
                "-I"
            ],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode != 0:
            return "Unknown"

        output = result.stdout

        for line in output.splitlines():
            line = line.strip()

            if line.startswith("SSID:"):
                return line.replace("SSID:", "").strip()

        return "Unknown"

    except Exception:
        return "Unknown"