# Cyber AI Agent

A Windows-friendly, local-first cybersecurity research and defense assistant designed for a 16 GB RAM laptop with optional cloud-model integration.

## Current scope

- Local Ollama chat interface
- Persistent SQLite notes and memory
- Heuristic analysis of local sample logs
- JSONL audit events
- Tests and GitHub Actions CI

This is a starter scaffold, not an autonomous penetration-testing system. Network scanning, exploitation, arbitrary shell execution, and automatic security changes are intentionally out of scope. Use security tools only on systems you own or are explicitly authorized to test.

## Quick start (Windows PowerShell)

1. Install Python 3.12+ and Ollama.
2. Download a small model: `ollama pull qwen2.5:3b`
3. Create a virtual environment and install dependencies:

   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   python -m pip install -r requirements.txt
   ```

4. Run `python -m cyberai`.
5. Enter `/help` for supported commands.

## Safety

- Run as a normal user, not Administrator.
- Do not store API keys, passwords, or other secrets in memory or source control.
- Treat retrieved content and logs as untrusted input.
- Review proposed code/rule changes before enabling them.

See [SECURITY.md](SECURITY.md) for the security model.
