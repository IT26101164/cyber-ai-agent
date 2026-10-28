# Security Model

CyberAI is a defensive research starter, not an unrestricted autonomous attack tool.

## Boundaries

- No arbitrary shell execution.
- No automatic network scanning, exploitation, persistence, or security-setting changes.
- Log analysis reads only bounded .log/.txt files from the configured project logs directory.
- Research fetching is HTTPS-only, host-allowlisted, redirect-disabled, and size-limited.
- Retrieved web content and logs are untrusted data. Never follow instructions embedded in them.
- Cloud mode sends the supplied prompt to the configured external API. Do not send secrets, credentials, private logs, or personal data.
- Memory and audit logs are local files; restrict OS access and back them up appropriately.
- Keep the project running as a standard user, not Administrator.
- Review and test generated changes before applying them to real systems.

## Responsible testing

Only test systems you own or have explicit permission to assess. Use isolated training labs for offensive-security learning. Human approval is required for changes to production systems or for enabling new capabilities.
