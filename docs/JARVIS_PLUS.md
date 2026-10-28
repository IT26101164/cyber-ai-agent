## JARVIS Plus dashboard (optional)

The original `python -m cyberai.jarvis_app` dashboard is preserved. The enhanced dashboard is a separate module:

```powershell
.\.venv\Scripts\python.exe -m cyberai.jarvis_plus
```

It adds an animated *synthetic* message-flow visual, fullscreen mode (F11; Esc exits), read-only TCP metadata with process names, and explainable heuristic triage hints. A hint is not a malware verdict; review the process and destination before drawing conclusions. No traffic payloads are captured and no connections are blocked or terminated.

Optional voice features:
```powershell
.\.venv\Scripts\python.exe -m pip install pyttsx3 SpeechRecognition pyaudio
```
Use **SPEAK STATUS** for text-to-speech and **VOICE COMMAND** for a one-shot microphone command. Speech recognition uses the optional SpeechRecognition Google recognizer, which may send the recognized audio to Google's service; don't use it for sensitive conversations. Without optional packages, the dashboard still runs and explains the missing voice capability. Supported commands include refresh, status, simulate, fullscreen, and pause.
