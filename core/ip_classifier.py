import ipaddress


def classify_ip_address(ip_address):
    try:
        ip = ipaddress.ip_address(ip_address)

        if ip.is_loopback:
            return {
                "classification": "Loopback/self address",
                "notes": "This address points back to the local device."
            }

        if ip.is_link_local:
            return {
                "classification": "Link-local/self-assigned address",
                "notes": "This address is usually used when the device cannot get normal network settings."
            }

        if ip.is_private:
            return {
                "classification": "Private/local address",
                "notes": "This address is used inside a local network, not directly on the public internet."
            }

        if ip.is_global:
            return {
                "classification": "Public address",
                "notes": "This address is globally routable on the internet."
            }

        if ip.is_multicast:
            return {
                "classification": "Multicast address",
                "notes": "This address is used for one-to-many network communication."
            }

        if ip.is_reserved:
            return {
                "classification": "Reserved address",
                "notes": "This address is reserved for special networking purposes."
            }

        return {
            "classification": "Special or unknown address",
            "notes": "WiFiGuard could not place this address into a common category."
        }

    except ValueError:
        return {
            "classification": "Invalid IP address",
            "notes": "This value could not be parsed as an IP address."
        }