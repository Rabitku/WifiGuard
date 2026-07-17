# (AI NOTES)

# GUI Preparation Notes

WiFiGuard is still a CLI project. This document records the backend boundary a future desktop GUI should use without adding any GUI dependency now.

## Backend Entry Point

A future GUI should call:

```python
from core.scan_runner import run_wifiguard_scan

scan_result = run_wifiguard_scan(network_context="unknown")
```

`network_context` should be one of:

- `"trusted"`
- `"public"`
- `"unknown"`

The GUI should collect that context in its own interface and pass it into the scan runner. The scan runner must not call `input()` or depend on terminal prompts.

## Returned Data

`run_wifiguard_scan()` returns one structured dictionary with report-ready data:

- `network_info`: local hostname and active local interfaces.
- `wifi_info`: current Wi-Fi name/status when macOS allows access.
- `dns_info`: local DNS server check result.
- `classified_active_interfaces`: local interface IP classifications.
- `classified_gateway`: default gateway IP classification.
- `classified_dns_servers`: DNS server classifications.
- `firewall_status`: local macOS firewall check result.
- `vpn_status`: local VPN/tunnel routing evidence.
- `gateway_info`: local default gateway check result.
- `sharing_services_status`: local sharing-service statuses.
- `network_context`: normalized network context used by the risk engine.
- `risk_result`: risk level, score, summary, findings, and recommendations.
- `check_results`: report-ready check rows that can be saved or displayed.

The returned dictionary is intended to be safe for both CLI printing and GUI rendering. GUI code should display this data directly rather than rerunning checks or recalculating risk.

## Modules The GUI Should Avoid Calling Directly

A future GUI should not call these modules directly for normal scans:

- `checks/*`: individual local checks should remain orchestrated by `core.scan_runner`.
- `core.risk_engine`: risk calculation should happen inside `run_wifiguard_scan()`.
- `cli_output.py`: terminal-only formatting and printing.
- `report_history.py`: terminal-only report-history prompts and display.
- `storage/database.py`: only call this from a dedicated persistence layer or controller code, not from scan execution.
- `main.py`: CLI argument parsing and terminal flow only.

## Shared CLI and GUI Flow

The CLI should continue to:

1. Parse command-line arguments in `main.py`.
2. Prompt for CLI-only context when running interactively.
3. Call `run_wifiguard_scan()`.
4. Save and prune local reports through `storage.database`.
5. Render output through `cli_output.py`.
6. Use `report_history.py` for interactive history viewing/deletion.

A future GUI should follow the same backend pattern:

1. Collect GUI-only context in the GUI.
2. Call `run_wifiguard_scan()`.
3. Render the returned dictionary in GUI views.
4. Save reports through an explicit GUI controller if local history is needed.

This keeps local scan logic in one backend path and prevents CLI prompts, printing, or database writes from being mixed into scan execution.

## Privacy Rule

The GUI must preserve WiFiGuard's local-only privacy design.

It must not add:

- Uploads of scan results.
- Telemetry or analytics.
- External lookups for DNS, IP, Wi-Fi, gateway, or device data.
- Network scanning of other devices.
- Packet capture, sniffing, attack, bypass, or intrusive behavior.

All checks should remain local, read-only, and defensive.
