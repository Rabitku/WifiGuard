import ipaddress

from core.known_dns import KNOWN_DNS_PROVIDERS


def normalise_ip_address(ip_address):

    return ip_address.split("%")[0].strip()


def classify_dns_server(dns_server):
    clean_dns_server = normalise_ip_address(dns_server)

    if clean_dns_server in KNOWN_DNS_PROVIDERS:
        provider_info = KNOWN_DNS_PROVIDERS[clean_dns_server]

        return {
            "server": dns_server,
            "classification": provider_info["type"],
            "provider": provider_info["provider"],
            "notes": provider_info["notes"]
        }

    try:
        ip = ipaddress.ip_address(clean_dns_server)

        if ip.is_loopback:
            return {
                "server": dns_server,
                "classification": "Loopback DNS",
                "provider": "This device",
                "notes": "This points back to the local device."
            }

        if ip.is_link_local:
            return {
                "server": dns_server,
                "classification": "Link-local DNS",
                "provider": "Local network",
                "notes": "This appears to be a link-local network address."
            }

        if ip.is_private:
            return {
                "server": dns_server,
                "classification": "Private/local DNS",
                "provider": "Local network",
                "notes": "This appears to be a private or local network DNS server."
            }

        return {
            "server": dns_server,
            "classification": "Network-provided or unknown public DNS",
            "provider": "Unknown",
            "notes": "WiFiGuard did not perform an online lookup to identify this DNS server."
        }

    except ValueError:
        return {
            "server": dns_server,
            "classification": "Invalid or unsupported DNS value",
            "provider": "Unknown",
            "notes": "This DNS value could not be parsed as an IP address."
        }


def classify_dns_servers(dns_servers):
    classified_servers = []

    for dns_server in dns_servers:
        classified_servers.append(classify_dns_server(dns_server))

    return classified_servers
