# CyberAI Architecture

## Runtime flow

1. The command-line interface accepts a prompt or an explicit slash command.
2. Normal prompts go to the local Ollama API at 127.0.0.1:11434.
3. The optional /cloud command sends only that prompt to the configured cloud API.
4. User-approved notes, bounded log-analysis reports, and research excerpts are stored in SQLite.
5. Operational events are appended to logs/audit.jsonl.
6. GitHub Actions installs dependencies and runs the unit tests on pull requests and pushes.

## Local-first defaults

- The default model is qwen2.5:3b, configurable with OLLAMA_MODEL.
- The cloud model is never selected automatically. Set OPENAI_API_KEY in the current shell before using /cloud.
- Prompts are not automatically copied to the cloud when local Ollama fails.
- The local SQLite database and audit log may contain sensitive material; restrict Windows account access.

## Resource expectations

A 3B quantized Ollama model is a reasonable starting point for a 16 GB RAM machine without a dedicated NVIDIA GPU. Actual speed and memory use depend on model quantization, context size, other running applications, and CPU performance.

## Current limitations

- This is a command-line starter, not a background service or endpoint protection product.
- Log analysis is rule-based and may produce false positives or miss threats.
- Research extraction is deliberately constrained and is not a complete HTML or PDF parser.
- The system does not autonomously run commands, scan networks, exploit hosts, or alter system security settings.
- Cloud mode requires a valid API key and may incur provider charges.

## Next engineering milestones

1. Add user interface and structured case management.
2. Add pluggable parsers for Windows Event Logs and common firewall logs.
3. Add source-cited knowledge retrieval and evaluation tests.
4. Add explicit approval gates for any future system-changing integrations.
5. Add packaging, signed releases, and dependency/security scanning.
