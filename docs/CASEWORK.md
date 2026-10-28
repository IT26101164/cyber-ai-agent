# CyberAI Case & Evidence Workbench

The Casework window is opened from **JARVIS Plus → Casework**. It stores data under the repository's ignored \`data/casework/\` folder by default.

## Capabilities

- Create local case records and update status (\`OPEN\`, \`INVESTIGATING\`, \`AWAITING_LEGAL_PROCESS\`, \`CLOSED\`).
- Import a selected local evidence file into a case-specific vault copy (up to 100 MiB). The original file is never modified.
- Record a provenance/source label and optional analyst description for each file.
- Calculate SHA-256 while copying and later verify the stored copy against the recorded hash.
- Extract IP addresses, domains, URLs, email addresses and 64-character SHA-256 values from supported text/log formats (up to 5 MiB for text parsing).
- Correlate the same indicator across separate evidence files and list the files where it appears.
- Build a timestamp-aware evidence timeline from hash-verified local text evidence. Supported formats include ISO-8601, Apache access-log timestamps and RFC-2822 mail dates.
- Link timestamped log lines to the evidence ID, filename, line number, SHA-256 and any indicators found on the same line. Repeated indicators across different timestamped evidence files are presented as leads, not identity attribution.
- Keep local audit history separate from evidence-derived events; the UI can show both in the timeline view.
- Record investigator notes and exportable JSON Lines audit events.
- Export a structured JSON case report (schema v2) containing case metadata, evidence hashes/provenance, extracted indicators, repeated-indicator leads, timestamped evidence timeline, timeline correlation leads, notes and an audit-timeline snapshot. The report is hashed and the export event is added to the live audit log.
- Verify a hash chain over audit events and validate stored note hashes.

## Start

From the repository root on Windows:

\`\`\`powershell
.\\.venv\\Scripts\\python.exe -m pytest -q
.\\.venv\\Scripts\\python.exe -m cyberai.jarvis_plus
\`\`\`

Click the **Casework** icon in the JARVIS left rail to open the workbench.

## Evidence integrity and limits

- Only import evidence you are authorized to possess and analyze.
- The app copies selected files into a local vault; it does not contact the source platform, phone, service provider, or any remote device.
- SHA-256 match means the stored copy matches the digest recorded at acquisition. It does not prove that the source is authentic, complete, or legally admissible.
- JSON case reports include metadata and analysis output, not the original evidence bytes. The export event is added to the live audit trail after the report snapshot, so the snapshot does not contain its own export event.
- Audit events are hash-chained and tamper-evident against casual edits, not digitally signed or impossible to alter by an attacker who controls the database. Export audit records promptly to a separately controlled location for formal workflows.
- Indicator matches are investigative leads, not identity attribution. Shared IP addresses/domains may be used by unrelated users; time, source, context and alternative explanations must be checked.
- Timeline extraction scans only supported text formats and up to 5 MiB per file. Files whose stored SHA-256 does not match the recorded digest are skipped and reported as warnings.
- Full dated timestamps are parsed; log fragments without a year are not guessed. Timestamps without an explicit timezone remain timezone-unknown and their placement relative to timezone-aware events is approximate. Device clock drift, parser limitations, and log manipulation can affect chronology.
- No threat-intelligence, geo-location, telecom, financial, law-enforcement or social-platform API is connected. The app does not find a person's live location.
- Database and evidence files are not encrypted by this module. Protect the Windows account and storage (for example, use device encryption/BitLocker where available), keep access restricted, and avoid storing unnecessary personal data.
- The default operator label is \`local-operator\`; set the \`CYBERAI_OPERATOR\` environment variable before launching to choose a more useful audit label. It is a label, not authentication.

This is a local investigation-organizing helper and not a certified forensic suite or substitute for jurisdiction-specific evidence handling rules and legal review.
