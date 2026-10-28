"""Benign, synthetic red/blue-team exercises. Never executes attacks or touches the OS."""

SCENARIOS = {
    "phishing": {
        "event": "SIMULATED: A message asks the user to sign in through an unfamiliar link.",
        "indicators": ["credential request from an unverified link", "urgency or impersonation"],
        "severity": "medium",
        "defenses": [
            "Report the message using the mail client's phishing-report feature.",
            "Verify the sender through a separate trusted channel.",
            "If credentials were entered, change them on the real service and enable MFA.",
        ],
    },
    "suspicious-powershell": {
        "event": "SIMULATED: A log entry contains an encoded PowerShell argument.",
        "indicators": ["encoded command-line argument", "unexpected scripting activity"],
        "severity": "high",
        "defenses": [
            "Preserve the event timestamp and command-line evidence; do not rerun the command.",
            "Review surrounding Windows event logs and the process parent/child chain.",
            "Run a Microsoft Defender scan and investigate any confirmed detections.",
        ],
    },
    "account-takeover": {
        "event": "SIMULATED: An account sign-in alert shows a device or location the owner does not recognize.",
        "indicators": ["unrecognized sign-in", "unexpected recovery-setting change"],
        "severity": "high",
        "defenses": [
            "Use the service's official security page to review sessions and sign out unknown sessions.",
            "Change the password from a trusted device and enable MFA or a passkey.",
            "Check recovery methods and connected apps; secure the linked email account too.",
        ],
    },
    "ransomware-warning": {
        "event": "SIMULATED: A monitoring alert reports rapid file changes and a suspicious note file.",
        "indicators": ["unusual file-change burst", "possible ransom-note artifact"],
        "severity": "critical",
        "defenses": [
            "If this is a real incident, disconnect the affected device from networks and preserve evidence.",
            "Do not open the suspicious files or attempt to execute samples.",
            "Use Microsoft Defender and your organization's incident-response process; restore only from known-good backups after containment.",
        ],
    },
}


def simulate(name: str) -> dict:
    """Return a deterministic synthetic event and response plan; perform no system actions."""
    key = name.strip().lower().replace("_", "-").replace(" ", "-")
    if key not in SCENARIOS:
        allowed = ", ".join(sorted(SCENARIOS))
        raise ValueError(f"Unknown simulation. Choose one of: {allowed}")
    scenario = SCENARIOS[key]
    return {
        "simulation": key,
        "mode": "synthetic-only",
        "severity": scenario["severity"],
        "event": scenario["event"],
        "indicators": list(scenario["indicators"]),
        "recommended_defenses": list(scenario["defenses"]),
        "execution": "No attack was run. No accounts, files, networks, or settings were accessed or changed.",
    }
