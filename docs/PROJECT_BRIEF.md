# WiFiGuard Project Brief

## Summary

WiFiGuard is a privacy-first desktop cybersecurity tool that helps users understand their security posture when connected to public Wi-Fi.

The first version will be macOS-focused and will run as a command-line prototype before becoming a desktop application.

## Problem

Public Wi-Fi is convenient but can expose users to additional security and privacy risks. Non-technical users often do not know whether basic protections such as a firewall, VPN, or safe network settings are in place.

## Goal

WiFiGuard aims to provide a simple, understandable security posture check for the user's current connection.

The app should not claim that a network is safe. Instead, it should explain whether the user's current setup appears lower risk, medium risk, higher risk, or unknown.

## Target Users

- Students
- Travellers
- Café workers
- Remote workers
- Non-technical users
- People using shared or public Wi-Fi

## MVP Scope

The MVP will check:

- active network interface
- local IP address
- DNS servers
- firewall status
- VPN-like interface detection
- HTTPS connectivity
- basic risk level
- simple recommendations

## Out of Scope

WiFiGuard will not:

- scan other devices
- sniff packets
- capture network traffic
- bypass captive portals
- test network passwords
- attack routers
- interfere with networks

## Success Criteria

The MVP is successful when it can:

- run locally on macOS
- collect basic network/security information
- produce a simple risk level
- explain findings in plain English
- output technical details for advanced users