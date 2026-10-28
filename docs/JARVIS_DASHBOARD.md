# CyberAI JARVIS Network Dashboard

A Windows desktop dashboard built with Python's standard-library Tkinter.

## Launch

From the repository root in PowerShell:

```powershell
.\.venv\Scripts\python.exe -m cyberai.jarvis_app
```

Or with a system Python that has Tkinter installed:

```powershell
python -m cyberai.jarvis_app
```

## Panels

- **Live Connection Telemetry:** reads the current Windows TCP connection table using a fixed, read-only PowerShell query. Shows local/remote endpoints, TCP state, and process ID. Refreshes every five seconds; manual refresh and pause controls are available.
- **Messaging Packet-Flow Lab:** creates a fictional three-hop device/gateway/relay timeline for learning. It does not contact WhatsApp or send messages.

## Important limitations

The live panel is a connection-table viewer, **not a packet sniffer**. It does not capture packet payloads, message contents, credentials, or WhatsApp data. A TCP connection row is not proof of a particular app's traffic. The simulation is fictional and explicitly labelled. This first version needs no Administrator privileges and does not change Windows settings or initiate network connections.

For real packet capture, add a separately reviewed capture backend later with explicit interface selection, consent, privacy filtering, and a dedicated permission boundary. Do not use this dashboard to access accounts or intercept other people's communications.
