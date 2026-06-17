import subprocess

def get_firewall_status():
    try:
        result = subprocess.run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"], capture_output=True, text=True)
        output = result.stdout.strip()
        if "enabled" in output:
            return {"Status": "Firewall is enabled",
                    "message": "Your firewall is active."}
        if "disabled" in output:
            return {"Status": "Firewall is disabled",
                    "message": "Your firewall is not active. This may expose your system to potential threats"}
        return {"Status": "Unknown", "message": "Unable to determine firewall status."}
            
    except Exception as e:
        print(f"Error occurred while fetching firewall status: {e}")
        