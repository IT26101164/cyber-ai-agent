"""Advanced single-screen JARVIS dashboard for defensive, read-only local telemetry.

Run: python -m cyberai.jarvis_plus
Optional voice: pip install pyttsx3 SpeechRecognition pyaudio

Traffic graph and messaging flow are explicitly synthetic illustrations. Live view
reads TCP connection metadata only; it does not capture packets or message contents.
"""
from __future__ import annotations

import json
import platform
import subprocess
import threading
from collections import Counter
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

BG = "#080e18"
SIDEBAR = "#0b1421"
PANEL = "#101b2b"
PANEL2 = "#142237"
LINE = "#20334a"
CYAN = "#53d9f5"
GREEN = "#58e6b0"
AMBER = "#f3c969"
RED = "#ff7185"
TEXT = "#e8f0fa"
MUTED = "#8499b3"

TCP_QUERY = (
    "Get-NetTCPConnection -ErrorAction SilentlyContinue | "
    "Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | "
    "ConvertTo-Json -Compress"
)
PROCESS_QUERY = "Get-Process | Select-Object Id,ProcessName | ConvertTo-Json -Compress"


def parse_json_rows(raw: str) -> list[dict[str, Any]]:
    """Parse PowerShell JSON that may contain one object or an array."""
    if not raw.strip():
        return []
    value = json.loads(raw)
    if isinstance(value, dict):
        value = [value]
    if not isinstance(value, list):
        raise ValueError("Expected a JSON object or array")
    return [row for row in value if isinstance(row, dict)]


def assess_connections(rows: list[dict[str, Any]], process_names: dict[str, str] | None = None) -> list[dict[str, Any]]:
    """Return explainable review hints, never a claim that a connection is malware."""
    names = process_names or {}
    counts: Counter[str] = Counter(str(row.get("OwningProcess", "")) for row in rows)
    alerts: list[dict[str, Any]] = []
    for row in rows:
        local = str(row.get("LocalAddress", ""))
        remote = str(row.get("RemoteAddress", ""))
        state = str(row.get("State", ""))
        pid = str(row.get("OwningProcess", ""))
        try:
            remote_port = int(row.get("RemotePort", 0) or 0)
        except (TypeError, ValueError):
            remote_port = 0
        score, reasons = 0, []
        if remote and remote not in ("0.0.0.0", "::", "127.0.0.1", "::1") and not remote.startswith("127."):
            if state.lower() == "established":
                score += 10
                reasons.append("Established remote TCP connection; common on normal devices")
        if state.lower() == "listen" and local in ("0.0.0.0", "::", "*"):
            score += 15
            reasons.append("Listening on all interfaces; verify that this service is expected")
        if counts[pid] >= 80:
            score += 20
            reasons.append("Process owns many TCP entries; check whether the workload explains this")
        if remote_port in (4444, 5555, 1337):
            score += 15
            reasons.append("Port sometimes appears in lab tooling; port number alone proves nothing")
        if score:
            level = "HIGH REVIEW" if score >= 40 else "REVIEW" if score >= 20 else "INFO"
            alerts.append({
                "level": level, "score": min(score, 100), "pid": pid,
                "process": names.get(pid, "Unknown process"),
                "local": f"{local}:{row.get('LocalPort', '')}",
                "remote": f"{remote}:{row.get('RemotePort', '')}",
                "state": state, "reason": "; ".join(reasons),
            })
    rank = {"HIGH REVIEW": 0, "REVIEW": 1, "INFO": 2}
    return sorted(alerts, key=lambda item: (rank[item["level"]], -item["score"]))


def get_live_data() -> tuple[list[dict[str, Any]], dict[str, str]]:
    """Read local Windows TCP metadata and process names via fixed read-only queries."""
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
    names = {str(item.get("Id")): str(item.get("ProcessName", "Unknown")) for item in processes}
    return rows, names


def simulated_hops() -> list[dict[str, str]]:
    """Fictional messaging-flow events; this helper performs no network I/O."""
    now = datetime.now().strftime("%H:%M:%S")
    return [
        {"time": now, "packet": "SIM-001", "source": "DEVICE", "destination": "LOCAL GATEWAY", "bytes": "384 B", "state": "OUTBOUND"},
        {"time": now, "packet": "SIM-002", "source": "LOCAL GATEWAY", "destination": "MESSAGING RELAY", "bytes": "1024 B", "state": "FORWARDED"},
        {"time": now, "packet": "SIM-003", "source": "MESSAGING RELAY", "destination": "RECIPIENT DEVICE", "bytes": "256 B", "state": "DELIVERED"},
    ]


def protocol_summary(rows: list[dict[str, Any]]) -> list[tuple[str, int]]:
    """Group observed TCP entries by common destination port; labels are approximate."""
    counts: Counter[str] = Counter()
    labels = {80: "HTTP", 443: "HTTPS/TLS", 53: "DNS over TCP", 22: "SSH", 3389: "RDP", 445: "SMB"}
    for row in rows:
        try:
            port = int(row.get("RemotePort", 0) or 0)
        except (TypeError, ValueError):
            port = 0
        label = labels.get(port, "Other TCP")
        counts[label] += 1
    return counts.most_common(5)


class JarvisPlus:
    def __init__(self, root: Any):
        self.root = root
        root.title("CYBERAI // JARVIS SECURITY OVERVIEW")
        root.geometry("1450x900")
        root.minsize(1120, 720)
        root.configure(bg=BG)
        self.rows: list[dict[str, Any]] = []
        self.names: dict[str, str] = {}
        self.current_alerts: list[dict[str, Any]] = []
        self.auto_refresh = True
        self.animation_phase = 0
        self.speech_engine = None
        self.last_error = ""
        self._style()
        self._build()
        self.refresh()
        self.animate()
        self.poll()

    def label(self, parent: Any, text: str, color: str = TEXT, size: int = 10, bold: bool = False):
        return tk.Label(parent, text=text, bg=parent.cget("bg"), fg=color,
                        font=("Segoe UI" if size < 13 else "Consolas", size, "bold" if bold else "normal"))

    def button(self, parent: Any, text: str, command: Any, color: str = CYAN):
        return tk.Button(parent, text=text, command=command, bg=PANEL2, fg=color,
                         activebackground="#23405a", activeforeground=TEXT, relief="flat",
                         bd=0, padx=11, pady=7, font=("Segoe UI", 9, "bold"), cursor="hand2")

    def _style(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background=PANEL, fieldbackground=PANEL, foreground=TEXT,
                        rowheight=25, borderwidth=0, font=("Consolas", 9))
        style.configure("Treeview.Heading", background=PANEL2, foreground=CYAN,
                        font=("Segoe UI", 9, "bold"), relief="flat")
        style.map("Treeview", background=[("selected", "#23405a")], foreground=[("selected", TEXT)])

    def _build(self):
        shell = tk.Frame(self.root, bg=BG)
        shell.pack(fill="both", expand=True)
        sidebar = tk.Frame(shell, bg=SIDEBAR, width=174, padx=12, pady=14)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        tk.Label(sidebar, text="◈ CYBERAI", bg=SIDEBAR, fg=CYAN,
                 font=("Consolas", 16, "bold")).pack(anchor="w", pady=(4, 2))
        self.label(sidebar, "J A R V I S  /  D E F E N S E", MUTED, 8, True).pack(anchor="w", pady=(0, 22))
        for name, command, color in (
            ("▦  Overview", lambda: None, CYAN),
            ("⌁  Connections", self.focus_connections, TEXT),
            ("⚑  Alerts", self.focus_alerts, TEXT),
            ("▷  Run simulation", self.simulate, GREEN),
            ("◖  Speak status", self.speak_status, TEXT),
            ("◉  Voice command", self.listen_once, TEXT),
            ("↻  Refresh data", self.refresh, TEXT),
            ("⛶  Fullscreen  F11", self.fullscreen, TEXT),
        ):
            self.button(sidebar, name, command, color).pack(fill="x", pady=3)
        tk.Frame(sidebar, bg=LINE, height=1).pack(fill="x", pady=16)
        tk.Label(sidebar, text="MONITOR MODE", bg=SIDEBAR, fg=MUTED,
                 font=("Segoe UI", 8, "bold")).pack(anchor="w")
        tk.Label(sidebar, text="● LOCAL / READ-ONLY", bg=SIDEBAR, fg=GREEN,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=5)
        self.label(sidebar, "No payload capture\nNo automatic blocking", AMBER, 8).pack(anchor="w", pady=(4, 0), side="bottom")

        main = tk.Frame(shell, bg=BG, padx=15, pady=12)
        main.pack(side="left", fill="both", expand=True)
        header = tk.Frame(main, bg=BG)
        header.pack(fill="x", pady=(0, 10))
        self.label(header, "Security Overview", TEXT, 19, True).pack(side="left")
        self.clock = self.label(header, "INITIALIZING", GREEN, 10, True)
        self.clock.pack(side="right")
        self.status = self.label(header, "● LOCAL TELEMETRY", GREEN, 9, True)
        self.status.pack(side="right", padx=16)

        cards = tk.Frame(main, bg=BG)
        cards.pack(fill="x", pady=(0, 10))
        self.conn_metric = self.metric(cards, "TCP CONNECTIONS", "—", CYAN)
        self.est_metric = self.metric(cards, "ESTABLISHED", "—", GREEN)
        self.process_metric = self.metric(cards, "PROCESSES SEEN", "—", AMBER)
        self.alert_metric = self.metric(cards, "REVIEW HINTS", "0", RED)

        upper = tk.Frame(main, bg=BG)
        upper.pack(fill="both", expand=True, pady=(0, 10))
        chart_panel = self.panel(upper, "01  /  NETWORK ACTIVITY VISUALIZATION", "Illustrative trend • simulated values, not measured throughput")
        chart_panel.pack(side="left", fill="both", expand=True, padx=(0, 6))
        self.chart = tk.Canvas(chart_panel, bg=PANEL, height=220, highlightthickness=0)
        self.chart.pack(fill="both", expand=True, pady=(8, 0))
        proto_panel = self.panel(upper, "02  /  TCP PORT PROFILE", "Approximate grouping from destination-port metadata")
        proto_panel.pack(side="left", fill="both", expand=True, padx=(6, 0))
        self.protocols = tk.Canvas(proto_panel, bg=PANEL, height=220, highlightthickness=0)
        self.protocols.pack(fill="both", expand=True, pady=(8, 0))

        lower = tk.Frame(main, bg=BG)
        lower.pack(fill="both", expand=True)
        connection_panel = self.panel(lower, "03  /  LIVE CONNECTIONS", "Local TCP metadata • select a row to inspect")
        connection_panel.pack(side="left", fill="both", expand=True, padx=(0, 6))
        cols = ("local", "remote", "state", "pid", "process")
        self.table = ttk.Treeview(connection_panel, columns=cols, show="headings", height=7)
        for col, title, width in (
            ("local", "LOCAL ENDPOINT", 130), ("remote", "REMOTE ENDPOINT", 130),
            ("state", "STATE", 82), ("pid", "PID", 55), ("process", "PROCESS", 105),
        ):
            self.table.heading(col, text=title)
            self.table.column(col, width=width, anchor="w")
        self.table.pack(fill="both", expand=True, pady=(8, 0))
        self.table.bind("<<TreeviewSelect>>", self.show_connection)
        self.connection_detail = self.label(connection_panel, "No connection selected.", MUTED, 8)
        self.connection_detail.pack(anchor="w", pady=(6, 0))

        right_stack = tk.Frame(lower, bg=BG)
        right_stack.pack(side="left", fill="both", expand=True, padx=(6, 0))
        alert_panel = self.panel(right_stack, "04  /  DEFENSIVE ALERTS", "Heuristic review hints • not malware verdicts")
        alert_panel.pack(fill="both", expand=True, pady=(0, 6))
        self.alerts = tk.Listbox(alert_panel, bg=PANEL, fg=TEXT, selectbackground="#23405a",
                                 font=("Consolas", 8), relief="flat", height=5, highlightthickness=0)
        self.alerts.pack(fill="both", expand=True, pady=(7, 0))
        self.alerts.bind("<<ListboxSelect>>", self.show_alert)
        self.timeline_panel = self.panel(right_stack, "05  /  SIMULATION TIMELINE", "Fictional messaging flow • no WhatsApp connection")
        self.timeline_panel.pack(fill="both", expand=True, pady=(6, 0))
        self.timeline = tk.Listbox(self.timeline_panel, bg=PANEL, fg=GREEN, selectbackground="#23405a",
                                   font=("Consolas", 8), relief="flat", height=4, highlightthickness=0)
        self.timeline.pack(fill="both", expand=True, pady=(7, 0))
        controls = tk.Frame(main, bg=BG)
        controls.pack(fill="x", pady=(9, 0))
        self.button(controls, "RUN SIMULATION", self.simulate, GREEN).pack(side="left")
        self.button(controls, "SPEAK STATUS", self.speak_status).pack(side="left", padx=6)
        self.button(controls, "VOICE COMMAND", self.listen_once, AMBER).pack(side="left")
        self.button(controls, "PAUSE POLLING", self.toggle_poll, AMBER).pack(side="left", padx=6)
        self.label(controls, "READ-ONLY • REVIEW BEFORE ACTION", MUTED, 8, True).pack(side="right")
        self.root.bind("<F11>", lambda _event: self.fullscreen())
        self.root.bind("<Escape>", lambda _event: self.root.attributes("-fullscreen", False))

    def panel(self, parent: Any, title: str, subtitle: str):
        frame = tk.Frame(parent, bg=PANEL, padx=11, pady=10, highlightthickness=1, highlightbackground=LINE)
        self.label(frame, title, CYAN, 10, True).pack(anchor="w")
        self.label(frame, subtitle, MUTED, 8).pack(anchor="w", pady=(3, 0))
        return frame

    def metric(self, parent: Any, title: str, value: str, color: str):
        frame = tk.Frame(parent, bg=PANEL, padx=13, pady=10, highlightthickness=1, highlightbackground=LINE)
        frame.pack(side="left", fill="x", expand=True, padx=(0, 7))
        self.label(frame, title, MUTED, 8, True).pack(anchor="w")
        label = self.label(frame, value, color, 16, True)
        label.pack(anchor="w", pady=(5, 0))
        return label

    def fullscreen(self):
        self.root.attributes("-fullscreen", not bool(self.root.attributes("-fullscreen")))

    def toggle_poll(self):
        self.auto_refresh = not self.auto_refresh
        self.status.configure(text="● AUTO-REFRESH ON" if self.auto_refresh else "● AUTO-REFRESH PAUSED",
                              fg=GREEN if self.auto_refresh else AMBER)

    def poll(self):
        self.clock.configure(text=datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
        if self.auto_refresh:
            self.refresh()
        self.root.after(10000, self.poll)

    def refresh(self):
        try:
            self.rows, self.names = get_live_data()
            self.last_error = ""
            for item in self.table.get_children():
                self.table.delete(item)
            for row in self.rows[:160]:
                pid = str(row.get("OwningProcess", ""))
                self.table.insert("", "end", values=(
                    f"{row.get('LocalAddress','')}:{row.get('LocalPort','')}",
                    f"{row.get('RemoteAddress','')}:{row.get('RemotePort','')}",
                    row.get("State", ""), pid, self.names.get(pid, "Unknown")))
            established = sum(str(row.get("State", "")).lower() == "established" for row in self.rows)
            self.conn_metric.configure(text=str(len(self.rows)))
            self.est_metric.configure(text=str(established))
            self.process_metric.configure(text=str(len({str(row.get('OwningProcess','')) for row in self.rows})))
            self.current_alerts = assess_connections(self.rows, self.names)
            self.alert_metric.configure(text=str(len(self.current_alerts)))
            self.alerts.delete(0, tk.END)
            for item in self.current_alerts[:35]:
                self.alerts.insert(tk.END, f"[{item['level']}] PID {item['pid']} {item['process']} → {item['remote']}")
            self.status.configure(text="● LIVE / READ-ONLY", fg=GREEN)
            self._draw_protocols()
        except Exception as exc:
            self.last_error = str(exc)[:180]
            self.conn_metric.configure(text="N/A")
            self.status.configure(text="● TELEMETRY UNAVAILABLE", fg=AMBER)
            self.alerts.delete(0, tk.END)
            self.alerts.insert(tk.END, "Live telemetry unavailable: " + self.last_error)
            self.alerts.insert(tk.END, "This is not evidence of an attack.")

    def _draw_protocols(self):
        c = self.protocols
        c.delete("all")
        width, height = max(c.winfo_width(), 260), max(c.winfo_height(), 190)
        summary = protocol_summary(self.rows)
        if not summary:
            c.create_text(width / 2, height / 2, text="No port metadata available", fill=MUTED)
            return
        maximum = max(count for _, count in summary) or 1
        left, right, top, bottom = 22, width - 14, 14, height - 35
        bar_space = max(25, (right - left) / len(summary))
        for index, (name, count) in enumerate(summary):
            x0 = left + index * bar_space + 5
            x1 = x0 + bar_space * .55
            y1 = bottom - (bottom - top) * count / maximum
            c.create_line(left, bottom, right, bottom, fill=LINE)
            c.create_rectangle(x0, y1, x1, bottom, fill=CYAN if index % 2 == 0 else AMBER, outline="")
            c.create_text((x0 + x1) / 2, max(top + 7, y1 - 9), text=str(count), fill=TEXT, font=("Consolas", 8))
            c.create_text((x0 + x1) / 2, bottom + 13, text=name, fill=MUTED, font=("Segoe UI", 7))

    def _draw_chart(self):
        c = self.chart
        c.delete("all")
        width, height = max(c.winfo_width(), 350), max(c.winfo_height(), 200)
        left, right, top, bottom = 36, width - 12, 15, height - 28
        for i in range(5):
            y = top + (bottom - top) * i / 4
            c.create_line(left, y, right, y, fill=LINE, dash=(2, 5))
            c.create_text(left - 15, y, text=str(100 - i * 25), fill=MUTED, font=("Consolas", 7))
        points = []
        # Entire line is illustrative; it is not a measurement of bytes or packet rate.
        for i in range(28):
            x = left + (right - left) * i / 27
            wave = (i * 7 + self.animation_phase * 3) % 17
            y = bottom - (bottom - top) * (18 + wave * 3) / 100
            points.extend((x, y))
        if len(points) >= 4:
            c.create_line(*points, fill=AMBER, width=2, smooth=True)
        c.create_text(width - 56, height - 9, text="SIMULATED", fill=AMBER, font=("Consolas", 7, "bold"))

    def animate(self):
        self.animation_phase = (self.animation_phase + 1) % 100
        self._draw_chart()
        self.root.after(180, self.animate)

    def simulate(self):
        self.timeline.delete(0, tk.END)
        for hop in simulated_hops():
            self.timeline.insert(tk.END, f"{hop['time']} {hop['packet']} {hop['source']} → {hop['destination']} {hop['bytes']} [{hop['state']}]")

    def focus_connections(self):
        children = self.table.get_children()
        if children:
            self.table.selection_set(children[0])
            self.table.focus(children[0])
            self.table.see(children[0])

    def focus_alerts(self):
        if self.alerts.size():
            self.alerts.selection_clear(0, tk.END)
            self.alerts.selection_set(0)
            self.alerts.event_generate("<<ListboxSelect>>")

    def show_connection(self, _event=None):
        selected = self.table.selection()
        if selected:
            values = self.table.item(selected[0], "values")
            self.connection_detail.configure(text=f"Endpoint: {values[0]} → {values[1]} | PID {values[3]} / {values[4]}")

    def show_alert(self, _event=None):
        selected = self.alerts.curselection()
        if not selected or selected[0] >= len(self.current_alerts):
            return
        item = self.current_alerts[selected[0]]
        messagebox.showinfo(
            "Explainable review hint",
            f"Level: {item['level']} | Heuristic score: {item['score']}\n"
            f"Process: {item['process']} (PID {item['pid']})\n"
            f"Local: {item['local']}\nRemote: {item['remote']}\nState: {item['state']}\n\n"
            f"Why shown: {item['reason']}\n\nThis is not proof of malicious activity. Verify the process, destination, and expected behavior.",
        )

    def speak_status(self):
        if pyttsx3 is None:
            self.voice_status_missing()
            return
        def worker():
            try:
                engine = pyttsx3.init()
                engine.say(f"JARVIS online. {len(self.rows)} TCP entries. {len(self.current_alerts)} review hints. Read only mode.")
                engine.runAndWait()
            except Exception:
                pass
        threading.Thread(target=worker, daemon=True).start()

    def voice_status_missing(self):
        messagebox.showinfo("Optional voice", "Text-to-speech is optional. Install with:\npython -m pip install pyttsx3")

    def listen_once(self):
        if sr is None:
            messagebox.showinfo("Optional voice input", "Voice input is optional. Install with:\npython -m pip install SpeechRecognition pyaudio")
            return
        self.status.configure(text="● LISTENING (ONE COMMAND)", fg=AMBER)
        def worker():
            try:
                recognizer = sr.Recognizer()
                with sr.Microphone() as source:
                    audio = recognizer.listen(source, timeout=4, phrase_time_limit=4)
                command = recognizer.recognize_google(audio).lower()
                self.root.after(0, lambda: self.handle_voice_command(command))
            except Exception:
                self.root.after(0, lambda: self.status.configure(text="● VOICE INPUT UNAVAILABLE", fg=AMBER))
        threading.Thread(target=worker, daemon=True).start()

    def handle_voice_command(self, command: str):
        self.status.configure(text="● VOICE COMMAND RECEIVED", fg=GREEN)
        if "refresh" in command or "status" in command:
            self.refresh()
            if "status" in command:
                self.speak_status()
        elif "simulate" in command or "message" in command:
            self.simulate()
        elif "fullscreen" in command:
            self.fullscreen()
        elif "pause" in command:
            self.toggle_poll()
        elif "alert" in command:
            self.focus_alerts()
        else:
            messagebox.showinfo("JARVIS command", "Try: refresh, status, simulate, fullscreen, pause, or alerts.")


def main():
    if tk is None or ttk is None:
        raise RuntimeError("Tkinter is unavailable. Install Python with Tcl/Tk support.")
    root = tk.Tk()
    JarvisPlus(root)
    root.mainloop()


if __name__ == "__main__":
    main()
