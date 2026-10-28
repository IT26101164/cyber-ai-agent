# JARVIS Plus — Advanced SOC Dashboard

Launch from the repository root on Windows:

```powershell
.\.venv\Scripts\python.exe -m cyberai.jarvis_plus
```

The original `cyberai.jarvis_app` remains available and unchanged. JARVIS Plus is a responsive, single-screen Security Operations Center-style overview with:

- Compact left navigation, live status, and KPI cards.
- Read-only local TCP connection metadata, owning PID, and process name.
- Explainable heuristic review hints with a reason and score; these are not malware verdicts.
- Approximate destination-port grouping based on TCP metadata, not deep packet inspection.
- Animated activity chart and network topology illustration clearly marked as synthetic.
- Advisory review workflow and synthetic messaging timeline.
- Optional text-to-speech and one-shot voice commands, plus button and keyboard alternatives.

## Optional voice

```powershell
.\.venv\Scripts\python.exe -m pip install pyttsx3 SpeechRecognition pyaudio
```

Text-to-speech uses the local OS voice engine when available. Voice input uses the optional Google speech recognizer and may send audio to Google's service. Do not use it for sensitive speech. The dashboard works without these packages.

## Data and safety boundaries

- Live data is limited to the local Windows TCP connection table and process names using fixed read-only PowerShell queries.
- No packet payloads or message contents are captured.
- The activity chart and messaging flow are fictional visual examples; they are not measured throughput and do not connect to WhatsApp.
- No external IP geolocation, threat-intelligence feed, vulnerability scan, or incident response action is claimed. Those require separately configured and authorized data sources.
- Alerts are triage hints only. Confirm process, destination, and expected business context before taking action.
- The application never automatically blocks connections, terminates processes, scans other devices, or changes security settings.
- Run as a standard Windows user, not Administrator.

## Verify

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```
