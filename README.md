# Cyber AI Agent

A Windows-friendly, local-first cybersecurity research and defense assistant designed for a 16 GB RAM laptop without a dedicated NVIDIA GPU. It uses Ollama locally and supports an optional, explicit cloud-model command.

## Features

- Local chat through Ollama
- SQLite memory for notes and selected analysis/research results
- Bounded heuristic analysis of \`.log\` and \`.txt\` files
- HTTPS research fetching from a small allowlist of documentation hosts
- JSONL audit events
- Optional cloud chat via \`/cloud\` (never automatic)
- Unit tests and GitHub Actions CI

This is a defensive research starter, not an autonomous penetration-testing or endpoint-protection system. It does not execute arbitrary shell commands, scan networks, exploit systems, or change security settings. Test only systems you own or are authorized to assess.

## Quick setup (Windows PowerShell)

1. Install **Python 3.12+** from [python.org](https://www.python.org/downloads/windows/) and **Ollama** from [ollama.com](https://ollama.com/download/windows).
2. Download/clone this repository and open PowerShell in its folder.
3. Run the setup script:

   \`\`\`powershell
   .\\setup.ps1
   \`\`\`

   The script creates \`.venv\`, installs Python dependencies, and downloads \`qwen2.5:3b\`. If PowerShell blocks local scripts, use this one-time command for the current terminal only, then run setup again:

   \`\`\`powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   .\\setup.ps1
   \`\`\`

4. Start the agent:

   \`\`\`powershell
   .\\run.ps1
   \`\`\`

   Or run \`\\.venv\\Scripts\\python.exe -m cyberai\` directly.

## Commands

| Command | Purpose |
|---|---|
| Normal text | Ask the local Ollama model |
| \`/remember TEXT\` | Save a note in local SQLite |
| \`/memory KEYWORDS\` | Search saved notes |
| \`/analyze-log FILE.log\` | Analyze a \`.log\` or \`.txt\` file placed inside \`logs\\\` |
| \`/research HTTPS_URL\` | Fetch a page from an allowlisted HTTPS documentation host |
| \`/cloud TEXT\` | Explicitly send a prompt to the configured cloud model |
| \`/help\` | Show command help |
| \`/quit\` | Exit |

Example safe log test: create \`logs\\sample.log\` with a few sample lines, then run \`/analyze-log sample.log\`.

## Optional cloud mode

Cloud mode is opt-in. It sends the text after \`/cloud\` to the provider and may incur charges. Do not send secrets, credentials, private logs, or personal data.

Set the API key only in the current PowerShell session:

\`\`\`powershell
$env:OPENAI_API_KEY = "YOUR_API_KEY"
$env:OPENAI_MODEL = "gpt-4.1-mini"
.\\run.ps1
\`\`\`

Then use \`/cloud your question\`. Do not paste API keys into chat, source files, SQLite memory, or audit logs. Close the PowerShell window to clear the session-scoped variable.

## Development and tests

\`\`\`powershell
.\\.venv\\Scripts\\python.exe -m pytest -q
\`\`\`

GitHub Actions also runs the tests for pushes and pull requests.

## Security and privacy

- Run as a standard user, not Administrator.
- Local notes and audit logs may contain sensitive data; protect the project folder with Windows account permissions.
- Treat web pages and logs as untrusted input.
- Research fetching is HTTPS-only, host-allowlisted, redirect-disabled, and size-limited.
- Local Ollama is the default. A local-model failure does not automatically send prompts to the cloud.
- Review results; heuristic matches are not proof of compromise.

Read [SECURITY.md](SECURITY.md) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for design details and limitations.
