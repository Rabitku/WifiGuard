from core.dns_classifier import classify_dns_server


def test_loopback_dns_is_classified_before_private_addresses():
    ipv4_result = classify_dns_server("127.0.0.1")
    ipv6_result = classify_dns_server("::1")

    assert ipv4_result["classification"] == "Loopback DNS"
    assert ipv4_result["provider"] == "This device"
    assert ipv6_result["classification"] == "Loopback DNS"
    assert ipv6_result["provider"] == "This device"


def test_link_local_dns_is_classified_before_private_addresses():
    ipv4_result = classify_dns_server("169.254.1.1")
    ipv6_result = classify_dns_server("fe80::1%en0")

    assert ipv4_result["classification"] == "Link-local DNS"
    assert ipv4_result["provider"] == "Local network"
    assert ipv6_result["classification"] == "Link-local DNS"
    assert ipv6_result["provider"] == "Local network"


def test_private_dns_classification_still_handles_common_home_networks():
    result = classify_dns_server("192.168.1.1")

    assert result["classification"] == "Private/local DNS"
    assert result["provider"] == "Local network"
