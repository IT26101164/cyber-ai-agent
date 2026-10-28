# Cyber AI Agent

A Windows-friendly, local-first cybersecurity research and defense assistant designed for a 16 GB RAM laptop without a dedicated NVIDIA GPU. It uses Ollama locally and supports an optional, explicit cloud-model command.

## Features

- Local chat through Ollama
- SQLite memory for notes and selected analysis/research results
- Bounded heuristic analysis of `.log` and `.txt` files
- Incident-response checklists for social account compromise, email compromise, suspicious Windows activity, and phishing
- Safe synthetic red/blue-team simulations with detection indicators and defensive recommendations
- Read-only Windows Security Health Check for Defender, Firewall profiles, and Windows Update service status
- Local-first Mastermind planning with saved plans, explicit human review, and audit events
- Capability Forge for approval-gated drafting of new text/code files into an isolated staging folder
- HTTPS research fetching from a small allowlist of documentation hosts
- JSONL audit events
- Optional cloud chat via `/cloud` (never automatic)
- Unit tests and GitHub Actions CI

The planning agent is advisory only: it stores plans, but it does not execute model-generated commands or actions. Approval records a human review for manual follow-through; it is not an automation permission. This is a defensive research starter, not a fully autonomous penetration-testing or endpoint-protection system. It does not break into accounts, bypass authentication, execute arbitrary shell commands, scan networks, exploit systems, or change security settings. Simulations are synthetic and do not perform real attacks. The health check runs only fixed, read-only PowerShell queries. Test only systems you own or are authorized to assess.

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
| `/plan GOAL` | Create a defensive plan for human review; no actions run |
| `/plans` | List saved plans and review status |
| `/approve PLAN_ID` | Mark a plan approved for manual follow-through only |
| `/reject PLAN_ID` | Reject a pending plan |
| `/forge GOAL` | Propose a new capability draft; writes no files until approved |
| `/forge-list` | List capability proposals and status |
| `/forge-approve ID` | Write approved draft files into `generated_capabilities/` staging |
| `/forge-reject ID` | Reject a capability proposal |
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

### Mastermind planning and human approval

The planning agent uses the configured local Ollama model by default. It turns a goal into a short, structured plan with assumptions, risk notes, validation criteria, and approval flags.

Example workflow:

1. Run `/plan Review the security posture of my own Windows laptop`.
2. Read the plan and its ID; new plans start as `pending_approval`.
3. Run `/plans` to review saved plan summaries.
4. Use `/approve PLAN_ID` or `/reject PLAN_ID` to record your decision.

Plans are stored locally in `data/plans.json`; plan creation and review decisions are recorded in `logs/audit.jsonl`. Protect these files because goals may contain sensitive context.

**Important control boundary:** approving a plan only marks it as reviewed for you to carry out manually. CyberAI does not execute plan steps, run model-generated shell commands, scan targets, or change settings. Keep work limited to your own laptop and explicitly authorized lab systems. This approval record is not a substitute for confirming scope before each active test.

### Capability Forge: approval-gated self-building

Use `/forge GOAL` to ask the local model to design a small capability. CyberAI stores a proposal and displays its draft files for review; it does not write the proposed files yet.

1. Run `/forge Create a local security report formatter`.
2. Inspect the proposed filenames, code, and review notes.
3. Run `/forge-approve ID` to write the approved draft under `generated_capabilities/ID/`, or `/forge-reject ID` to reject it.
4. Run `/forge-list` to see proposal status and staging paths.

The Forge permits at most three flat text files per proposal, with bounded file sizes and a small allowlist of extensions. It does not overwrite existing files or change existing application source. Generated Python is **never automatically imported, executed, installed, or tested**. The staging folder is not an active plugin directory. Review the code manually before using it; integration into CyberAI requires a separate change and review. This is a controlled first step toward self-building, not unrestricted self-modification or a guarantee that any requested feature can be built.

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


## JARVIS-style Windows desktop dashboard

Launch the separate visual dashboard from the repository root:

```powershell
.\\.venv\\Scripts\\python.exe -m cyberai.jarvis_app
```

It provides a dark desktop UI with a read-only Windows TCP connection-table view (local/remote endpoint, state, and PID) plus a separate simulated messaging packet-flow lab. The simulation is fictional and does not connect to WhatsApp or send messages. The live view displays connection metadata only; it is not a packet sniffer and does not reveal encrypted message contents. No Administrator privileges or extra Python packages are required for this first version.

See [docs/JARVIS_DASHBOARD.md](docs/JARVIS_DASHBOARD.md) for launch instructions and limitations.


### JARVIS Plus dashboard (enhanced, optional)

Run the original dashboard with `python -m cyberai.jarvis_app`, or the enhanced version with:

```powershell
.\\.venv\\Scripts\\python.exe -m cyberai.jarvis_plus
```

JARVIS Plus adds animated synthetic network flow, F11 fullscreen (Esc exits), process names for read-only TCP connection metadata, and explainable heuristic triage hints. Hints are not malware verdicts; verify the context. It never captures payloads or blocks/kills connections. Optional voice packages: `python -m pip install pyttsx3 SpeechRecognition pyaudio`. Voice recognition may send recognized audio to Google's service; avoid using it for sensitive speech. The dashboard works without voice extras.


## Case & Evidence Workbench (JARVIS Plus)

The JARVIS Plus desktop UI includes a **Casework** icon that opens the local investigation workbench. It supports case register/status, local evidence-file import into a vault copy, provenance labels, SHA-256 verification, text-file indicator extraction, cross-evidence correlations, investigator notes, UTC audit timeline, hash-chain verification and JSONL export.

Run from the repository root:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m cyberai.jarvis_plus
```

The evidence vault and database are stored under the ignored `data/casework/` directory. Evidence is not uploaded. The Phone Intelligence Desk records local phone-number leads and manually entered, evidence-linked location records from authorized sources; it does not locate phones from numbers, hack devices, or query providers. Opening a map sends selected coordinates to OpenStreetMap only after confirmation. Indicator matches are investigative leads and do not attribute a crime to a person. The audit is tamper-evident, not digitally signed; evidence is not encrypted by this module. Phone numbers and coordinates are sensitive: protect exports and review [docs/CASEWORK.md](docs/CASEWORK.md) before using real-world evidence.
