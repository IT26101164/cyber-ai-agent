# Cyber AI Agent

A Windows-friendly, local-first cybersecurity research and defense assistant designed for a 16 GB RAM laptop without a dedicated NVIDIA GPU. It uses Ollama locally and supports an optional, explicit cloud-model command.

## Features

- Local chat through Ollama
- SQLite memory for notes and selected analysis/research results
- Bounded heuristic analysis of `.log` and `.txt` files
- Incident-response checklists for social account compromise, email compromise, suspicious Windows activity, and phishing
- Safe synthetic red/blue-team simulations with detection indicators and defensive recommendations
- Read-only Windows Security Health Check for Defender, Firewall profiles, and Windows Update service status
- HTTPS research fetching from a small allowlist of documentation hosts
- JSONL audit events
- Optional cloud chat via `/cloud` (never automatic)
- Unit tests and GitHub Actions CI

This is a defensive research starter, not a fully autonomous penetration-testing or endpoint-protection system. It does not break into accounts, bypass authentication, execute arbitrary shell commands, scan networks, exploit systems, or change security settings. Simulations are synthetic and do not perform real attacks. The health check runs only fixed, read-only PowerShell queries. Test only systems you own or are authorized to assess.

## Quick setup (Windows PowerShell)

1. Install **Python 3.12+** from https://www.python.org/downloads/windows/ and **Ollama** from https://ollama.com/download/windows.
2. Download or clone this repository and open PowerShell in its folder.
3. Run ` .\setup.ps1` in PowerShell (omit the leading space inside the code formatting). If scripts are blocked, first run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`.
4. Start the agent with ` .\run.ps1` (omit the leading space inside the code formatting).

## Commands

| Command | Purpose |
|---|---|
| Normal text | Ask the local Ollama model |
| `/remember TEXT` | Save a note in local SQLite |
| `/memory KEYWORDS` | Search saved notes |
| `/analyze-log FILE.log` | Analyze a `.log` or `.txt` file inside `logs\` |
| `/incident TYPE` | Show a defensive incident-response checklist |
| `/simulate SCENARIO` | Run a synthetic red/blue exercise; no real attack is executed |
| `/healthcheck` | Read-only Windows Defender, Firewall, and Update service status |
| `/research HTTPS_URL` | Fetch a page from an allowlisted HTTPS documentation host |
| `/cloud TEXT` | Explicitly send a prompt to the configured cloud model |
| `/help` | Show commands |
| `/quit` | Exit |

Incident checklist examples:

- `/incident social-account-compromise`
- `/incident email-compromise`
- `/incident windows-suspicious-activity`
- `/incident phishing`

Simulation examples:

- `/simulate phishing`
- `/simulate suspicious-powershell`
- `/simulate account-takeover`
- `/simulate ransomware-warning`

Simulations generate fictional events, indicators, and defense recommendations only. They do not run commands, access accounts, modify files, or touch networks. Incident checklists are guidance, not automatic account recovery. For social platforms, use their official recovery flow; never share one-time codes or pay strangers claiming they can recover an account.

### Windows Security Health Check

Run `/healthcheck` from CyberAI on Windows. It reads a small snapshot of Microsoft Defender status, Windows Firewall profile states, and the Windows Update service state. It does not change settings, start services, scan files, or prove that the device is malware-free. If a status is unknown, verify it in the Windows Security app. The command is unsupported on non-Windows systems.

Example safe log test: create `logs\sample.log` with a few sample lines, then run `/analyze-log sample.log`.

## Optional cloud mode

Cloud mode is opt-in. It sends the text after `/cloud` to the provider and may incur charges. Do not send secrets, credentials, private logs, or personal data.

Set the API key only in the current PowerShell session:

```powershell
$env:OPENAI_API_KEY = "YOUR_API_KEY"
$env:OPENAI_MODEL = "gpt-4.1-mini"
.\run.ps1
```

Then use `/cloud your question`. Do not paste API keys into chat, source files, SQLite memory, or audit logs. Close the PowerShell window to clear the session-scoped variable.

## Development and tests

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

GitHub Actions also runs the tests for pushes and pull requests.

## Security and privacy

- Run as a standard user, not Administrator.
- Local notes and audit logs may contain sensitive data; protect the project folder with Windows account permissions.
- Treat web pages and logs as untrusted input.
- Research fetching is HTTPS-only, host-allowlisted, redirect-disabled, and size-limited.
- Local Ollama is the default. A local-model failure does not automatically send prompts to the cloud.
- Review results; heuristic matches are not proof of compromise.

Read [SECURITY.md](SECURITY.md) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for design details and limitations.
