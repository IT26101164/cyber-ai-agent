"""Human-reviewed incident-response checklists; no accounts or systems are modified."""

PLAYBOOKS = {
    "social-account-compromise": {
        "title": "Social media account may be compromised",
        "steps": [
            "Use the platform's official compromised-account recovery page from a trusted device.",
            "Secure the linked email account first; change its password if it may also be compromised.",
            "From official security settings, review active sessions and sign out unknown sessions if you can still access the account.",
            "Change the account password to a unique one and enable an authenticator or passkey where available.",
            "Review recovery email/phone, connected apps, recent posts/messages, and security alerts; remove unfamiliar items.",
            "If locked out, use the provider's official identity-verification and recovery process. Never pay a stranger who promises recovery or share verification codes.",
            "Warn contacts about suspicious messages, preserve screenshots and alert emails, and report the compromise to the platform.",
        ],
    },
    "email-compromise": {
        "title": "Email account may be compromised",
        "steps": [
            "From a trusted device, change the email password to a unique password if you can sign in.",
            "Use the provider's official security page to sign out other sessions and review recent sign-ins.",
            "Check recovery methods, forwarding rules, filters, app passwords, and connected applications for changes you did not make.",
            "Enable multifactor authentication and regenerate recovery codes if exposed.",
            "Secure other accounts that use this email for password resets; change reused passwords.",
            "Preserve alerts and timestamps, and contact the provider through its official support channel if locked out.",
        ],
    },
    "windows-suspicious-activity": {
        "title": "Suspicious activity on this Windows PC",
        "steps": [
            "Do not run the suspicious file or command again; record its exact text, time, and where it came from.",
            "If active compromise is suspected, disconnect Wi-Fi/Ethernet to limit remote activity; avoid deleting evidence.",
            "Run Windows Security / Microsoft Defender full scan, then review Protection History.",
            "Review Windows Security alerts and relevant event logs; treat indicators as leads, not proof.",
            "From a separate trusted device, change important passwords if credentials may have been exposed.",
            "Install Windows and application updates after preserving useful evidence; seek qualified incident-response help for serious cases.",
        ],
    },
    "phishing": {
        "title": "Possible phishing message",
        "steps": [
            "Do not open attachments, run downloads, or enter credentials from the message.",
            "Verify the request using a known, independent contact method; do not rely on links or phone numbers in the message.",
            "Report the message using the mail or platform's built-in reporting tool.",
            "If you entered a password, change it on the real service using a trusted device and enable multifactor authentication.",
            "If you entered payment or banking details, contact the bank using the number on its official card or website.",
            "Keep the message and headers if your security team needs them; avoid forwarding malicious attachments casually.",
        ],
    },
}


def get_playbook(name: str) -> dict:
    """Return a copy of a known checklist, rejecting unknown scenario names."""
    key = name.strip().lower().replace("_", "-").replace(" ", "-")
    if key not in PLAYBOOKS:
        allowed = ", ".join(sorted(PLAYBOOKS))
        raise ValueError(f"Unknown incident type. Choose one of: {allowed}")
    playbook = PLAYBOOKS[key]
    return {
        "type": key,
        "title": playbook["title"],
        "steps": list(playbook["steps"]),
        "notice": "Checklist only: CyberAI does not access accounts, reset credentials, or make changes automatically.",
    }
