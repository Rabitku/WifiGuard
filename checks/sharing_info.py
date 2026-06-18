import socket
import subprocess


def run_command(command):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode != 0:
            return None

        return result.stdout.strip()

    except Exception:
        return None


def check_process_active(process_name):
    result = run_command(["pgrep", "-x", process_name])
    return bool(result)


def is_local_port_open(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            return True
    except Exception:
        return False


def check_file_sharing():
    if check_process_active("smbd"):
        return {
            "service": "File Sharing",
            "status": "Active",
            "confidence": "Medium",
            "message": "The SMB file sharing service appears to be running."
        }

    return {
        "service": "File Sharing",
        "status": "Not active",
        "confidence": "Medium",
        "message": "The SMB file sharing service does not appear to be running."
    }


def check_screen_sharing():
    if check_process_active("screensharingd"):
        return {
            "service": "Screen Sharing",
            "status": "Active",
            "confidence": "Medium",
            "message": "The screen sharing service appears to be running."
        }

    return {
        "service": "Screen Sharing",
        "status": "Not active",
        "confidence": "Medium",
        "message": "The screen sharing service does not appear to be running."
    }


def check_remote_login():
    output = run_command(["systemsetup", "-getremotelogin"])

    if output:
        if "On" in output:
            return {
                "service": "Remote Login",
                "status": "Enabled",
                "confidence": "High",
                "message": "Remote Login appears to be enabled."
            }

        if "Off" in output:
            return {
                "service": "Remote Login",
                "status": "Disabled",
                "confidence": "High",
                "message": "Remote Login appears to be disabled."
            }

    if is_local_port_open(22):
        return {
            "service": "Remote Login",
            "status": "Possibly active",
            "confidence": "Medium",
            "message": "Port 22 is open locally, which may indicate SSH/Remote Login is active."
        }

    return {
        "service": "Remote Login",
        "status": "Not active or unavailable",
        "confidence": "Medium",
        "message": "Remote Login could not be confirmed, and local SSH port 22 does not appear open."
    }


def check_remote_management():
    if check_process_active("ARDAgent"):
        return {
            "service": "Remote Management",
            "status": "Active",
            "confidence": "Medium",
            "message": "Apple Remote Management appears to be active."
        }

    return {
        "service": "Remote Management",
        "status": "Not active",
        "confidence": "Medium",
        "message": "Apple Remote Management does not appear to be active."
    }


def check_remote_apple_events():
    output = run_command(["systemsetup", "-getremoteappleevents"])

    if output:
        if "On" in output:
            return {
                "service": "Remote Apple Events",
                "status": "Enabled",
                "confidence": "High",
                "message": "Remote Apple Events appears to be enabled."
            }

        if "Off" in output:
            return {
                "service": "Remote Apple Events",
                "status": "Disabled",
                "confidence": "High",
                "message": "Remote Apple Events appears to be disabled."
            }

    return {
        "service": "Remote Apple Events",
        "status": "Unknown",
        "confidence": "Low",
        "message": "WiFiGuard could not determine Remote Apple Events status without elevated permissions."
    }


def check_printer_sharing():
    output = run_command(["cupsctl"])

    if output is None:
        return {
            "service": "Printer Sharing",
            "status": "Unknown",
            "confidence": "Low",
            "message": "WiFiGuard could not determine Printer Sharing status."
        }

    if "_share_printers=1" in output or "share_printers=1" in output:
        return {
            "service": "Printer Sharing",
            "status": "Enabled",
            "confidence": "Medium",
            "message": "Printer Sharing appears to be enabled."
        }

    return {
        "service": "Printer Sharing",
        "status": "Disabled or not active",
        "confidence": "Medium",
        "message": "Printer Sharing does not appear to be enabled."
    }


def get_sharing_services_status():
    return [
        check_file_sharing(),
        check_screen_sharing(),
        check_remote_login(),
        check_remote_management(),
        check_remote_apple_events(),
        check_printer_sharing()
    ]