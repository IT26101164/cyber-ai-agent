# JARVIS Plus — Incident Management SOC Dashboard

Launch from the repository root on Windows:

```powershell
.\.venv\Scripts\python.exe -m cyberai.jarvis_plus
```

The original `cyberai.jarvis_app` remains available and unchanged. JARVIS Plus now uses a cinematic black/teal Incident Management layout inspired by the user's reference:

- Compact icon rail and top filter/search treatment.
- KPI cards for live local TCP entries, established entries, unique process IDs, and heuristic review hints.
- Incident health gauge calculated from local heuristic hint count. It is not a security verdict.
- Editable-looking network-topology schematic with review/normal node colors; it does not infer real routes or geolocation.
- Incident lifecycle and incident register are sample UI data, not a connected SIEM feed.
- Live TCP connection table and demonstration incident table share the centre panel; use the two view buttons to switch between them.
- Recent review hints with process/PID and endpoint details.
- Explainable local analyst note and a sample incident volume trend.
- Visible Flow Lab popup for a synthetic three-hop message route; it performs no network I/O.
- Optional local text-to-speech and one-shot voice commands through the Speak and Voice buttons, with manual refresh and keyboard alternatives.

## Optional voice

```powershell
.\.venv\Scripts\python.exe -m pip install pyttsx3 SpeechRecognition pyaudio
```

Text-to-speech uses the local OS voice engine when available. Voice input uses the optional Google speech recognizer and may send audio to Google's service. Do not use it for sensitive speech. The dashboard works without these packages.

## Data and safety boundaries

- Live data is limited to this Windows device's TCP connection metadata and process names using fixed read-only PowerShell queries.
- No packet payloads or message contents are captured.
- Incident cases, lifecycle, topology, and volume chart are explicitly sample/synthetic visual data; they are not a live incident feed or measured throughput.
- Port labels are approximate groupings by TCP destination port, not deep packet inspection.
- No external IP geolocation, threat-intelligence feed, or vulnerability scan is claimed.
- Heuristic alerts are review hints only. Confirm process, destination, and expected context before taking action.
- The app never automatically blocks connections, terminates processes, scans other devices, or changes security settings.
- Run as a standard Windows user, not Administrator.

## Verify

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```


## Case & Evidence Workbench

Open **Casework** from the left icon rail in JARVIS Plus. This launches the local case manager. It supports local case records, selected-file evidence import and SHA-256, text indicator extraction, cross-file correlation leads, investigator notes, a tamper-evident event chain and JSONL export.

Full documentation: [CASEWORK.md](CASEWORK.md). This workbench uses local data only; it does not query police databases, telecom operators, social platforms, location services or external threat feeds. Evidence storage is not encrypted by this module, so protect the Windows user profile and drive.
