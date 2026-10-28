"""Read-only Windows security posture checks using a fixed PowerShell script."""

import json
import platform
import subprocess


_POWERSHELL_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$mp = Get-MpComputerStatus
$profiles = @(Get-NetFirewallProfile | ForEach-Object {
    [ordered]@{ name = $_.Name; enabled = [bool]$_.Enabled }
})
$wu = Get-Service -Name wuauserv
$antivirus = $null
$realtime = $null
if ($null -ne $mp) {
    $antivirus = [bool]$mp.AntivirusEnabled
    $realtime = [bool]$mp.RealTimeProtectionEnabled
}
$updateStatus = $null
if ($null -ne $wu) { $updateStatus = [string]$wu.Status }
[ordered]@{
    defender_available = ($null -ne $mp)
    antivirus_enabled = $antivirus
    real_time_protection_enabled = $realtime
    firewall_profiles = $profiles
    windows_update_service = $updateStatus
} | ConvertTo-Json -Depth 4 -Compress
"""


def collect_windows_posture() -> dict:
    """Collect a small read-only snapshot. Never accepts or executes user-supplied commands."""
    if platform.system() != "Windows":
        return {
            "supported": False,
            "message": "Windows Security Health Check runs only on Windows.",
            "findings": [],
        }

    try:
        completed = subprocess.run(
            [
                "powershell.exe",
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                _POWERSHELL_SCRIPT,
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(
            "Could not complete the read-only Windows check. Verify PowerShell is available and try again."
        ) from exc

    if completed.returncode != 0:
        raise RuntimeError("PowerShell could not read Windows security status.")

    try:
        data = json.loads(completed.stdout)
    except (json.JSONDecodeError, TypeError) as exc:
        raise RuntimeError("Windows security status returned unreadable data.") from exc
    if not isinstance(data, dict):
        raise RuntimeError("Windows security status returned an unexpected result.")

    findings = []
    if data.get("defender_available") is False:
        findings.append("Microsoft Defender status could not be read; verify your installed security provider.")
    elif data.get("real_time_protection_enabled") is False:
        findings.append("Microsoft Defender real-time protection appears to be disabled.")
    elif data.get("real_time_protection_enabled") is None:
        findings.append("Real-time protection status is unknown; check Windows Security manually.")

    profiles = data.get("firewall_profiles") or []
    disabled_profiles = [
        profile.get("name", "unknown")
        for profile in profiles
        if isinstance(profile, dict) and profile.get("enabled") is False
    ]
    if disabled_profiles:
        findings.append("Windows Firewall appears disabled for: " + ", ".join(disabled_profiles) + ".")
    if not profiles:
        findings.append("Windows Firewall profile status could not be read; check Windows Security manually.")

    return {
        "supported": True,
        "mode": "read-only",
        "status": {
            "defender_available": data.get("defender_available"),
            "antivirus_enabled": data.get("antivirus_enabled"),
            "real_time_protection_enabled": data.get("real_time_protection_enabled"),
            "firewall_profiles": profiles,
            "windows_update_service": data.get("windows_update_service"),
        },
        "findings": findings,
        "note": (
            "This is a limited status snapshot, not a malware scan or proof that the device is clean. "
            "Windows Update service status alone does not show whether updates are current. "
            "No settings were changed."
        ),
    }
