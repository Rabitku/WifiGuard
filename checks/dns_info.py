import subprocess
import re


def get_dns_servers():
    try:
        result = subprocess.run(
            ["scutil", "--dns"],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode != 0:
            return []

        dns_servers = []

        for line in result.stdout.splitlines():
            line = line.strip()

            match = re.match(r"nameserver\[\d+\]\s*:\s*(.+)", line)

            if match:
                dns_server = match.group(1).strip()

                if dns_server not in dns_servers:
                    dns_servers.append(dns_server)

        return dns_servers

    except Exception:
        return []