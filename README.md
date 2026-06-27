# WiFiGuard

**Know your connection. Reduce your risk. Privacy matters.**

WiFiGuard is a macOS-first cybersecurity project designed to help users understand their connection safety when using public Wi-Fi.

The tool performs local, read-only checks on the user's own device and connection. It is designed with accessibility, privacy, and defensive security as the priorities.

## Project Goals

- Help users understand public Wi-Fi risks
- Perform safe local checks on the user's own device
- Provide simple recommendations
- Demonstrate Python, networking, defensive security, documentation, and developer skills

## Ethical Priorities

WiFiGuard is designed to run locally and help users make safer decisions when connected to public Wi-Fi.

WiFiGuard is not designed to perform unethical, illegal, or intrusive actions. The project avoids any functionality that scans, attacks, captures, bypasses, or interferes with networks or third-party devices.

WiFiGuard does not:

- Scan other devices
- Sniff traffic
- Capture packets
- Bypass captive portals
- Attack networks
- Test Wi-Fi passwords
- Interfere with routers or access points

## Current CLI Features

WiFiGuard currently performs local, read-only checks for:

- Current network information and local IP address
- Current Wi-Fi network name when macOS allows it
- Default gateway details
- DNS configuration and local DNS classification
- macOS firewall status
- VPN/tunnel routing evidence
- Common macOS sharing services
- Basic risk level and plain-English recommendations
- Local SQLite report history through `--history` and `--clear-history`

Automated tests run on pushes and pull requests with GitHub Actions.

## macOS Wi-Fi Name Limitation

On some macOS versions, the connected Wi-Fi network name may be hidden by macOS privacy controls and shown as `<redacted>`.

This is not a security risk.

When this happens, WiFiGuard displays:

```text
Hidden by macOS privacy settings
```

## Disclaimer

WiFiGuard provides guidance based on local checks. It cannot guarantee that a Wi-Fi network is safe.
