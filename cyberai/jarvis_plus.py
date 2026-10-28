"""Enhanced JARVIS dashboard: animated synthetic flow, read-only TCP telemetry, alerts, optional voice.

Run: python -m cyberai.jarvis_plus
Voice extras (optional): pip install pyttsx3 SpeechRecognition pyaudio
"""
from __future__ import annotations

import json
import platform
import subprocess
import threading
from datetime import datetime
from typing import Any

try:
    import tkinter as tk
    from tkinter import ttk, messagebox
except ImportError:  # Headless CI can still import helper functions.
    tk = None  # type: ignore[assignment]
    ttk = None  # type: ignore[assignment]
    messagebox = None  # type: ignore[assignment]

try:
    import pyttsx3  # type: ignore[import-not-found]
except ImportError:
    pyttsx3 = None

try:
    import speech_recognition as sr  # type: ignore[import-not-found]
except ImportError:
    sr = None

BG, PANEL, ALT = "#07111f", "#0d1b2a", "#102338"
CYAN, GREEN, AMBER, RED = "#4de4ff", "#4dffb5", "#ffc857", "#ff657a"
TEXT, MUTED = "#e8f4ff", "#8ca7bd"

TCP_QUERY = (
    "Get-NetTCPConnection -ErrorAction SilentlyContinue | "
    "Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | "
    "ConvertTo-Json -Compress"
)
PROCESS_QUERY = "Get-Process | Select-Object Id,ProcessName | ConvertTo-Json -Compress"


def parse_json_rows(raw: str) -> list[dict[str, Any]]:
    if not raw.strip():
        return []
    value = json.loads(raw)
    if isinstance(value, dict):
        value = [value]
    if not isinstance(value, list):
        raise ValueError("Expected a JSON object or array")
    return [row for row in value if isinstance(row, dict)]


def assess_connections(rows: list[dict[str, Any]], process_names: dict[str, str] | None = None) -> list[dict[str, Any]]:
    """Explainable triage hints only; never label a connection as confirmed malware."""
    names = process_names or {}
    counts: dict[str, int] = {}
    for row in rows:
        pid = str(row.get("OwningProcess", ""))
        counts[pid] = counts.get(pid, 0) + 1
    alerts: list[dict[str, Any]] = []
    for row in rows:
        local = str(row.get("LocalAddress", ""))
        remote = str(row.get("RemoteAddress", ""))
        state = str(row.get("State", "")).lower()
        pid = str(row.get("OwningProcess", ""))
        try:
            remote_port = int(row.get("RemotePort", 0) or 0)
        except (TypeError, ValueError):
            remote_port = 0
        score, reasons = 0, []
        if remote and remote not in ("0.0.0.0", "::", "127.0.0.1", "::1") and not remote.startswith("127."):
            if state == "established":
                score += 10
                reasons.append("established remote connection (common and not suspicious by itself)")
        if state == "listen" and local in ("0.0.0.0", "::", "*"):
            score += 15
            reasons.append("listening on a wildcard interface; verify whether this is expected")
        if counts.get(pid, 0) >= 80:
            score += 20
            reasons.append("process owns many TCP entries; check whether workload explains this")
        if remote_port in (4444, 5555, 1337):
            score += 15
            reasons.append("remote port is sometimes used in labs; port alone is not proof of abuse")
        if score:
            level = "HIGH" if score >= 40 else "REVIEW" if score >= 20 else "INFO"
            alerts.append({
                "level": level, "score": min(score, 100), "pid": pid,
                "process": names.get(pid, "Unknown process"),
                "local": f"{local}:{row.get('LocalPort', '')}",
                "remote": f"{remote}:{row.get('RemotePort', '')}",
                "state": str(row.get("State", "")),
                "reason": "; ".join(reasons),
            })
    rank = {"HIGH": 0, "REVIEW": 1, "INFO": 2}
    return sorted(alerts, key=lambda item: (rank[item["level"]], -item["score"]))


def get_live_data() -> tuple[list[dict[str, Any]], dict[str, str]]:
    if platform.system() != "Windows":
        raise OSError("Live connection view requires Windows.")
    def run(query: str) -> str:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", query],
            capture_output=True, text=True, timeout=8, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if result.returncode:
            raise RuntimeError((result.stderr.strip() or "PowerShell query failed")[:240])
        return result.stdout
    rows = parse_json_rows(run(TCP_QUERY))
    processes = parse_json_rows(run(PROCESS_QUERY))
    names = {str(p.get("Id")): str(p.get("ProcessName", "Unknown")) for p in processes}
    return rows, names


def simulated_hops() -> list[dict[str, str]]:
    now = datetime.now().strftime("%H:%M:%S")
    return [
        {"time": now, "packet": "SIM-001", "source": "DEVICE", "destination": "LOCAL GATEWAY", "bytes": "384 B", "state": "OUTBOUND"},
        {"time": now, "packet": "SIM-002", "source": "LOCAL GATEWAY", "destination": "MESSAGING RELAY", "bytes": "1024 B", "state": "FORWARDED"},
        {"time": now, "packet": "SIM-003", "source": "MESSAGING RELAY", "destination": "RECIPIENT DEVICE", "bytes": "256 B", "state": "DELIVERED"},
    ]


class JarvisPlus:
    def __init__(self, root: Any):
        self.root = root
        root.title("CYBERAI // JARVIS PLUS")
        root.geometry("1320x850")
        root.minsize(1000, 680)
        root.configure(bg=BG)
        self.rows: list[dict[str, Any]] = []
        self.names: dict[str, str] = {}
        self.auto_refresh = True
        self.animation_phase = 0
        self.speech_engine = None
        self._ui()
        self.refresh()
        self.animate()
        self.poll()

    def label(self, parent: Any, text: str, color: str = TEXT, size: int = 10, bold: bool = False):
        return tk.Label(parent, text=text, bg=parent.cget("bg"), fg=color,
                        font=("Consolas", size, "bold" if bold else "normal"))

    def button(self, parent: Any, text: str, command: Any, color: str = CYAN):
        return tk.Button(parent, text=text, command=command, bg=ALT, fg=color,
                         activebackground="#17445b", activeforeground=TEXT, relief="flat",
                         bd=0, padx=12, pady=7, font=("Consolas", 9, "bold"), cursor="hand2")

    def _ui(self):
        header = tk.Frame(self.root, bg=BG, padx=18, pady=12); header.pack(fill="x")
        self.label(header, "C Y B E R A I  /  J A R V I S +", CYAN, 20, True).pack(side="left")
        self.clock = self.label(header, "LOCAL / READ-ONLY", GREEN, 10, True); self.clock.pack(side="right")
        bar = tk.Frame(self.root, bg=BG, padx=18); bar.pack(fill="x")
        self.conn_count = self.metric(bar, "TCP CONNECTIONS", "—", CYAN)
        self.alert_count = self.metric(bar, "TRIAGE HINTS", "0", AMBER)
        self.voice_status = self.metric(bar, "VOICE", "OPTIONAL", GREEN)
        body = tk.Frame(self.root, bg=BG, padx=18, pady=12); body.pack(fill="both", expand=True)
        left = tk.Frame(body, bg=PANEL, padx=10, pady=10); left.pack(side="left", fill="both", expand=True, padx=(0, 6))
        right = tk.Frame(body, bg=PANEL, padx=10, pady=10); right.pack(side="left", fill="both", expand=True, padx=(6, 0))
        self.label(left, "01 / LIVE TCP TELEMETRY", CYAN, 11, True).pack(anchor="w")
        self.label(left, "Connection metadata only • no packet payloads", MUTED, 9).pack(anchor="w", pady=5)
        cols = ("local", "remote", "state", "pid", "process")
        self.table = ttk.Treeview(left, columns=cols, show="headings", height=10)
        for col, width in zip(cols, (145, 145, 90, 55, 110)):
            self.table.heading(col, text=col.upper()); self.table.column(col, width=width, anchor="w")
        self.table.pack(fill="both", expand=True)
        row = tk.Frame(left, bg=PANEL); row.pack(fill="x", pady=8)
        self.button(row, "REFRESH", self.refresh).pack(side="left")
        self.button(row, "PAUSE POLL", self.toggle_poll, AMBER).pack(side="left", padx=6)
        self.button(row, "FULLSCREEN (F11)", self.fullscreen, GREEN).pack(side="left")
        self.label(left, "02 / DEFENSIVE TRIAGE HINTS", AMBER, 10, True).pack(anchor="w", pady=(8, 4))
        self.alerts = tk.Listbox(left, bg="#081522", fg=TEXT, selectbackground="#17445b",
                                 font=("Consolas", 9), relief="flat", height=7)
        self.alerts.pack(fill="both", expand=True)
        self.alerts.bind("<<ListboxSelect>>", self.show_alert)
        self.label(right, "03 / ANIMATED SIMULATION LAB", GREEN, 11, True).pack(anchor="w")
        self.label(right, "Fictional message route • no WhatsApp connection", MUTED, 9).pack(anchor="w", pady=5)
        self.graph = tk.Canvas(right, bg="#081522", height=250, highlightthickness=1, highlightbackground="#1d3b50")
        self.graph.pack(fill="x")
        row2 = tk.Frame(right, bg=PANEL); row2.pack(fill="x", pady=8)
        self.button(row2, "RUN SIMULATION", self.simulate, GREEN).pack(side="left")
        self.button(row2, "SPEAK STATUS", self.speak_status, CYAN).pack(side="left", padx=6)
        self.button(row2, "VOICE COMMAND", self.listen_once, AMBER).pack(side="left")
        self.timeline = tk.Listbox(right, bg="#081522", fg=TEXT, selectbackground="#17445b",
                                   font=("Consolas", 9), relief="flat", height=9)
        self.timeline.pack(fill="both", expand=True, pady=(6, 0))
        self.label(self.root, "READ-ONLY • TRIAGE IS HEURISTIC • VERIFY BEFORE TAKING ACTION", AMBER, 9).pack(pady=8)
        self.root.bind("<F11>", lambda _e: self.fullscreen())
        self.root.bind("<Escape>", lambda _e: self.root.attributes("-fullscreen", False))

    def metric(self, parent: Any, title: str, value: str, color: str):
        card = tk.Frame(parent, bg=PANEL, padx=12, pady=9, highlightthickness=1, highlightbackground="#1a354a")
        card.pack(side="left", fill="x", expand=True, padx=4, pady=4)
        self.label(card, title, MUTED, 9, True).pack(anchor="w")
        value_label = self.label(card, value, color, 14, True); value_label.pack(anchor="w", pady=(4, 0))
        return value_label

    def fullscreen(self):
        self.root.attributes("-fullscreen", not bool(self.root.attributes("-fullscreen")))

    def toggle_poll(self):
        self.auto_refresh = not self.auto_refresh

    def poll(self):
        self.clock.configure(text=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        if self.auto_refresh:
            self.refresh()
        self.root.after(8000, self.poll)

    def refresh(self):
        try:
            self.rows, self.names = get_live_data()
            for item in self.table.get_children(): self.table.delete(item)
            for row in self.rows[:250]:
                pid = str(row.get("OwningProcess", ""))
                self.table.insert("", "end", values=(
                    f"{row.get('LocalAddress','')}:{row.get('LocalPort','')}",
                    f"{row.get('RemoteAddress','')}:{row.get('RemotePort','')}",
                    row.get("State", ""), pid, self.names.get(pid, "Unknown")))
            findings = assess_connections(self.rows, self.names)
            self.alerts.delete(0, tk.END)
            for item in findings[:100]:
                self.alerts.insert(tk.END, f"[{item['level']}] PID {item['pid']} {item['process']} | {item['remote']}")
            self.conn_count.configure(text=str(len(self.rows)))
            self.alert_count.configure(text=str(len(findings)))
            self.current_alerts = findings
        except Exception as exc:
            self.conn_count.configure(text="N/A")
            self.alerts.delete(0, tk.END)
            self.alerts.insert(tk.END, "Live telemetry unavailable: " + str(exc)[:150])

    def show_alert(self, _event=None):
        selected = self.alerts.curselection()
        findings = getattr(self, "current_alerts", [])
        if selected and selected[0] < len(findings):
            item = findings[selected[0]]
            messagebox.showinfo("Explainable triage hint",
                f"Level: {item['level']}  |  Heuristic score: {item['score']}\n"
                f"Process: {item['process']} (PID {item['pid']})\n"
                f"Local: {item['local']}\nRemote: {item['remote']}\nState: {item['state']}\n\n"
                f"Why shown: {item['reason']}\n\nThis is not proof of malicious activity. Verify process, destination, and business context.")

    def _draw_graph(self):
        c = self.graph; c.delete("all")
        w, h = max(c.winfo_width(), 360), max(c.winfo_height(), 250)
        pts = [(w*.15,h*.45,"DEVICE"), (w*.5,h*.25,"GATEWAY"), (w*.85,h*.45,"RELAY")]
        for a,b in ((pts[0],pts[1]),(pts[1],pts[2])):
            c.create_line(a[0],a[1],b[0],b[1],fill="#1e647c",width=2,dash=(4,4))
        for x,y,name in pts:
            c.create_oval(x-27,y-27,x+27,y+27,fill="#103448",outline=CYAN,width=2)
            c.create_text(x,y,text="●",fill=GREEN,font=("Consolas",16))
            c.create_text(x,y+42,text=name,fill=TEXT,font=("Consolas",8,"bold"))
        # The moving dot is a fictional visual indicator, never a real packet.
        t = (self.animation_phase % 100) / 100
        for (a,b) in ((pts[0],pts[1]),(pts[1],pts[2])):
            x, y = a[0] + (b[0]-a[0])*t, a[1] + (b[1]-a[1])*t
            c.create_oval(x-5,y-5,x+5,y+5,fill=AMBER,outline="")
        c.create_text(w/2,h-18,text="SIMULATED ENCRYPTED MESSAGE FLOW",fill=MUTED,font=("Consolas",8))

    def animate(self):
        self.animation_phase = (self.animation_phase + 2) % 100
        self._draw_graph()
        self.root.after(80, self.animate)

    def simulate(self):
        self.timeline.delete(0, tk.END)
        for hop in simulated_hops():
            self.timeline.insert(tk.END, f"{hop['time']} {hop['packet']} {hop['source']} -> {hop['destination']} {hop['bytes']} [{hop['state']}]")

    def speak_status(self):
        if pyttsx3 is None:
            self.voice_status.configure(text="TTS NOT INSTALLED")
            messagebox.showinfo("Optional voice", "For spoken responses, run:\npython -m pip install pyttsx3")
            return
        def worker():
            try:
                engine = pyttsx3.init()
                engine.say(f"JARVIS online. {len(self.rows)} TCP entries. {len(getattr(self, 'current_alerts', []))} triage hints. Read only mode.")
                engine.runAndWait()
                self.root.after(0, lambda: self.voice_status.configure(text="SPEECH READY"))
            except Exception:
                self.root.after(0, lambda: self.voice_status.configure(text="VOICE UNAVAILABLE"))
        threading.Thread(target=worker, daemon=True).start()

    def listen_once(self):
        if sr is None:
            messagebox.showinfo("Optional voice input", "Voice input is optional. Install with:\npython -m pip install SpeechRecognition pyaudio\nIf microphone setup fails, use the buttons and keyboard shortcuts.")
            return
        def worker():
            try:
                recognizer = sr.Recognizer()
                with sr.Microphone() as source:
                    audio = recognizer.listen(source, timeout=4, phrase_time_limit=4)
                command = recognizer.recognize_google(audio).lower()
                self.root.after(0, lambda: self.handle_voice_command(command))
            except Exception as exc:
                self.root.after(0, lambda: self.voice_status.configure(text=f"VOICE INPUT FAILED"))
        self.voice_status.configure(text="LISTENING...")
        threading.Thread(target=worker, daemon=True).start()

    def handle_voice_command(self, command: str):
        self.voice_status.configure(text="VOICE READY")
        if "refresh" in command or "status" in command:
            self.refresh()
            if "status" in command: self.speak_status()
        elif "simulate" in command or "message" in command:
            self.simulate()
        elif "fullscreen" in command:
            self.fullscreen()
        elif "pause" in command:
            self.toggle_poll()
        else:
            messagebox.showinfo("JARVIS command", "Try: refresh, status, simulate, fullscreen, or pause.")


def main():
    if tk is None or ttk is None:
        raise RuntimeError("Tkinter is unavailable. Install a Python build with Tcl/Tk support.")
    root = tk.Tk()
    JarvisPlus(root)
    root.mainloop()


if __name__ == "__main__":
    main()
