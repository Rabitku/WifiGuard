def calculate_basic_risk(network_info):
    active_interfaces = network_info.get("active_interfaces", [])

    if not active_interfaces:
        return {
            "level": "Unknown",
            "message": "No active network connection was detected."
        }

    return {
        "level": "Medium risk",
        "message": "You are connected to a network. More checks are needed before making recommendations."
    }