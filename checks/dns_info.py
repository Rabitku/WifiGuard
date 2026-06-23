import subprocess
import re


def get_dns_servers():
    dns_info = get_dns_info()
    return dns_info["servers"]


def get_dns_info():
    try:
        result = subprocess.run(
            ["scutil", "--dns"],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode != 0:
            return {
                "status": "Unavailable",
                "servers": [],
                "message": "WiFiGuard could not verify DNS servers on this Mac."
            }

        dns_servers = []

        for line in result.stdout.splitlines():
            line = line.strip()

            match = re.match(r"nameserver\[\d+\]\s*:\s*(.+)", line)

            if match:
                dns_server = match.group(1).strip()

                if dns_server not in dns_servers:
                    dns_servers.append(dns_server)

        if dns_servers:
            return {
                "status": "Detected",
                "servers": dns_servers,
                "message": f"{len(dns_servers)} DNS server(s) detected."
            }

        return {
            "status": "Not detected",
            "servers": [],
            "message": "The DNS check completed, but no DNS servers were detected."
        }

    except Exception:
        return {
            "status": "Check failed",
            "servers": [],
            "message": "WiFiGuard could not complete the DNS check."
        }
