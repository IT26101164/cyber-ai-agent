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
    "Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,@{Name='State';Expression={$_.State.ToString()}},OwningProcess | "
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
        local, remote = str(row.get("LocalAddress", "")), str(row.get("RemoteAddress", ""))
        state, pid = str(row.get("State", "")), str(row.get("OwningProcess", ""))
        try:
            remote_port = int(row.get("RemotePort", 0) or 0)
        except (TypeError, ValueError):
            remote_port = 0
        score, reasons = 0, []
        if remote and remote not in ("0.0.0.0", "::", "127.0.0.1", "::1") and not remote.startswith("127."):
            if state.lower() == "established":
                score += 10
                reasons.append("Established remote connection; common on normal devices")
        if state.lower() == "listen" and local in ("0.0.0.0", "::", "*"):
            score += 15
            reasons.append("Listening on all interfaces; verify this service is expected")
        if counts[pid] >= 80:
            score += 20
            reasons.append("Process owns many TCP entries; verify whether its workload explains this")
        if remote_port in (4444, 5555, 1337):
            score += 15
            reasons.append("Port sometimes appears in labs; port alone is not proof of abuse")
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
    """Read local Windows TCP metadata and process names using fixed read-only queries."""
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
    """Fictional message flow events; no network I/O occurs."""
    now = datetime.now().strftime("%H:%M:%S")
    return [
        {"time": now, "packet": "SIM-001", "source": "DEVICE", "destination": "LOCAL GATEWAY", "bytes": "384 B", "state": "OUTBOUND"},
        {"time": now, "packet": "SIM-002", "source": "LOCAL GATEWAY", "destination": "MESSAGING RELAY", "bytes": "1024 B", "state": "FORWARDED"},
        {"time": now, "packet": "SIM-003", "source": "MESSAGING RELAY", "destination": "RECIPIENT DEVICE", "bytes": "256 B", "state": "DELIVERED"},
    ]


def protocol_summary(rows: list[dict[str, Any]]) -> list[tuple[str, int]]:
    """Approximate labels from TCP destination ports; not deep packet inspection."""
    counts: Counter[str] = Counter()
    labels = {80: "HTTP", 443: "HTTPS/TLS", 53: "DNS/TCP", 22: "SSH", 3389: "RDP", 445: "SMB"}
    for row in rows:
        try:
            port = int(row.get("RemotePort", 0) or 0)
        except (TypeError, ValueError):
            port = 0
        counts[labels.get(port, "Other TCP")] += 1
    return counts.most_common(5)


class JarvisPlus:
    """Responsive SOC-style dashboard for read-only local telemetry."""

    def __init__(self, root: Any):
        self.root = root
        root.title("CYBERAI // JARVIS SECURITY OPERATIONS")
        root.geometry("1280x800")
        root.minsize(1050, 680)
        root.configure(bg=BG)
        self.rows: list[dict[str, Any]] = []
        self.names: dict[str, str] = {}
        self.current_alerts: list[dict[str, Any]] = []
        self.auto_refresh = True
        self.animation_phase = 0
        self.trend = [18, 22, 17, 26, 21, 30, 25, 19, 28, 23, 34, 26, 31, 22, 29, 24]
        self._style()
        self._build()
        self.refresh()
        self.animate()
        self.poll()

    def label(self, parent: Any, text: str, color: str = TEXT, size: int = 9, bold: bool = False):
        return tk.Label(parent, text=text, bg=parent.cget("bg"), fg=color,
                        font=("Segoe UI" if size < 13 else "Consolas", size, "bold" if bold else "normal"),
                        anchor="w")

    def button(self, parent: Any, text: str, command: Any, color: str = CYAN):
        return tk.Button(parent, text=text, command=command, bg=PANEL2, fg=color,
                         activebackground="#23405a", activeforeground=TEXT, relief="flat",
                         bd=0, padx=9, pady=6, font=("Segoe UI", 8, "bold"), cursor="hand2")

    def _style(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background=PANEL, fieldbackground=PANEL, foreground=TEXT,
                        rowheight=22, borderwidth=0, font=("Consolas", 8))
        style.configure("Treeview.Heading", background=PANEL2, foreground=CYAN,
                        font=("Segoe UI", 8, "bold"), relief="flat")
        style.map("Treeview", background=[("selected", "#23405a")], foreground=[("selected", TEXT)])

    def panel(self, parent: Any, title: str, subtitle: str = ""):
        frame = tk.Frame(parent, bg=PANEL, padx=9, pady=8, highlightthickness=1, highlightbackground=LINE)
        self.label(frame, title, CYAN, 9, True).pack(anchor="w")
        if subtitle:
            self.label(frame, subtitle, MUTED, 7).pack(anchor="w", pady=(2, 0))
        return frame

    def metric(self, parent: Any, title: str, value: str, color: str):
        frame = tk.Frame(parent, bg=PANEL, padx=10, pady=8, highlightthickness=1, highlightbackground=LINE)
        self.label(frame, title, MUTED, 7, True).pack(anchor="w")
        val = self.label(frame, value, color, 15, True)
        val.pack(anchor="w", pady=(3, 0))
        return frame, val

    def _build(self):
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        shell = tk.Frame(self.root, bg=BG)
        shell.grid(row=0, column=0, sticky="nsew")
        shell.grid_rowconfigure(0, weight=1)
        shell.grid_columnconfigure(1, weight=1)
        side = tk.Frame(shell, bg=SIDEBAR, width=145, padx=9, pady=12)
        side.grid(row=0, column=0, sticky="ns")
        side.grid_propagate(False)
        tk.Label(side, text="◈ CYBERAI", bg=SIDEBAR, fg=CYAN, font=("Consolas", 14, "bold")).pack(anchor="w")
        self.label(side, "JARVIS / DEFENSE", MUTED, 7, True).pack(anchor="w", pady=(2, 15))
        nav = [
            ("▦  Overview", lambda: None, CYAN), ("⌁  Network", self.focus_connections, TEXT),
            ("⚑  Alerts", self.focus_alerts, TEXT), ("◎  Processes", self.focus_processes, TEXT),
            ("▷  Simulate", self.simulate, GREEN), ("◖  Speak status", self.speak_status, TEXT),
            ("◉  Voice command", self.listen_once, TEXT), ("↻  Refresh", self.refresh, TEXT),
            ("⛶  Fullscreen", self.fullscreen, TEXT),
        ]
        for text, command, color in nav:
            self.button(side, text, command, color).pack(fill="x", pady=2)
        tk.Frame(side, bg=LINE, height=1).pack(fill="x", pady=12)
        self.label(side, "MONITOR MODE", MUTED, 7, True).pack(anchor="w")
        self.label(side, "● LOCAL / READ-ONLY", GREEN, 8, True).pack(anchor="w", pady=4)
        self.label(side, "No payload capture\nNo auto-blocking", AMBER, 7).pack(anchor="w", pady=(2, 0))
        self.label(side, "F11 fullscreen\nEsc to exit", MUTED, 7).pack(side="bottom", anchor="w")

        main = tk.Frame(shell, bg=BG, padx=10, pady=9)
        main.grid(row=0, column=1, sticky="nsew")
        main.grid_rowconfigure(2, weight=3)
        main.grid_rowconfigure(3, weight=4)
        main.grid_columnconfigure(0, weight=1)

        header = tk.Frame(main, bg=BG)
        header.grid(row=0, column=0, sticky="ew", pady=(0, 7))
        self.label(header, "Security Operations Overview", TEXT, 16, True).pack(side="left")
        self.clock = self.label(header, "INITIALIZING", GREEN, 8, True)
        self.clock.pack(side="right")
        self.status = self.label(header, "● LOCAL TELEMETRY", GREEN, 8, True)
        self.status.pack(side="right", padx=12)

        cards = tk.Frame(main, bg=BG)
        cards.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        for col in range(4):
            cards.grid_columnconfigure(col, weight=1, uniform="metrics")
        self.conn_metric = self.metric(cards, "TCP CONNECTIONS", "—", CYAN)[1]
        self.est_metric = self.metric(cards, "ESTABLISHED", "—", GREEN)[1]
        self.process_metric = self.metric(cards, "PROCESSES SEEN", "—", AMBER)[1]
        self.alert_metric = self.metric(cards, "REVIEW HINTS", "0", RED)[1]
        for i, (title, value, color) in enumerate((
            ("TCP CONNECTIONS", "—", CYAN), ("ESTABLISHED", "—", GREEN),
            ("PROCESSES SEEN", "—", AMBER), ("REVIEW HINTS", "0", RED)
        )):
            # Replace the metric label created above with a single compact card.
            for child in cards.grid_slaves(row=0, column=i):
                child.destroy()
            card, val = self.metric(cards, title, value, color)
            card.grid(row=0, column=i, sticky="ew", padx=(0 if i == 0 else 4, 0))
            if i == 0: self.conn_metric = val
            elif i == 1: self.est_metric = val
            elif i == 2: self.process_metric = val
            else: self.alert_metric = val

        upper = tk.Frame(main, bg=BG)
        upper.grid(row=2, column=0, sticky="nsew", pady=(0, 8))
        for col, weight in enumerate((3, 3, 4)):
            upper.grid_columnconfigure(col, weight=weight, uniform="upper")
        upper.grid_rowconfigure(0, weight=1)

        trend_panel = self.panel(upper, "01  /  ACTIVITY TREND", "Illustrative values • not measured throughput")
        trend_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 4))
        self.trend_canvas = tk.Canvas(trend_panel, bg=PANEL, highlightthickness=0, height=150)
        self.trend_canvas.pack(fill="both", expand=True, pady=(5, 0))

        map_panel = self.panel(upper, "02  /  NETWORK TOPOLOGY", "Live endpoints are not geolocated")
        map_panel.grid(row=0, column=1, sticky="nsew", padx=4)
        self.map_canvas = tk.Canvas(map_panel, bg=PANEL, highlightthickness=0, height=150)
        self.map_canvas.pack(fill="both", expand=True, pady=(5, 0))

        alert_panel = self.panel(upper, "03  /  RECENT REVIEW HINTS", "Explainable heuristics • verify before action")
        alert_panel.grid(row=0, column=2, sticky="nsew", padx=(4, 0))
        self.alerts = tk.Listbox(alert_panel, bg=PANEL, fg=TEXT, selectbackground="#23405a",
                                 font=("Consolas", 8), relief="flat", height=6, highlightthickness=0)
        self.alerts.pack(fill="both", expand=True, pady=(5, 0))
        self.alerts.bind("<<ListboxSelect>>", self.show_alert)

        lower = tk.Frame(main, bg=BG)
        lower.grid(row=3, column=0, sticky="nsew")
        lower.grid_columnconfigure(0, weight=6, uniform="lower")
        lower.grid_columnconfigure(1, weight=4, uniform="lower")
        lower.grid_rowconfigure(0, weight=1)
        conn_panel = self.panel(lower, "04  /  LIVE CONNECTIONS", "Windows TCP metadata • select a row for details")
        conn_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 4))
        cols = ("local", "remote", "state", "pid", "process")
        self.table = ttk.Treeview(conn_panel, columns=cols, show="headings", height=7)
        for col, title, width in (
            ("local", "LOCAL ENDPOINT", 125), ("remote", "REMOTE ENDPOINT", 125),
            ("state", "STATE", 72), ("pid", "PID", 52), ("process", "PROCESS", 90),
        ):
            self.table.heading(col, text=title)
            self.table.column(col, width=width, anchor="w")
        self.table.pack(fill="both", expand=True, pady=(5, 0))
        self.table.bind("<<TreeviewSelect>>", self.show_connection)
        self.connection_detail = self.label(conn_panel, "Select a row to inspect connection metadata.", MUTED, 7)
        self.connection_detail.pack(anchor="w", pady=(4, 0))

        right = tk.Frame(lower, bg=BG)
        right.grid(row=0, column=1, sticky="nsew", padx=(4, 0))
        right.grid_rowconfigure(0, weight=3)
        right.grid_rowconfigure(1, weight=2)
        right.grid_columnconfigure(0, weight=1)
        insights = self.panel(right, "05  /  AI DEFENSIVE INSIGHTS", "Rule-based explanations from local metadata")
        insights.grid(row=0, column=0, sticky="nsew", pady=(0, 4))
        self.insight_list = tk.Listbox(insights, bg=PANEL, fg=TEXT, selectbackground="#23405a",
                                       font=("Segoe UI", 8), relief="flat", height=4, highlightthickness=0)
        self.insight_list.pack(fill="both", expand=True, pady=(5, 0))
        attack = self.panel(right, "06  /  RESPONSE WORKFLOW", "Advisory only • no automatic remediation")
        attack.grid(row=1, column=0, sticky="nsew", pady=(4, 0))
        self.workflow = tk.Canvas(attack, bg=PANEL, height=65, highlightthickness=0)
        self.workflow.pack(fill="both", expand=True, pady=(4, 0))
        controls = tk.Frame(main, bg=BG)
        controls.grid(row=4, column=0, sticky="ew", pady=(7, 0))
        self.button(controls, "RUN SYNTHETIC FLOW", self.simulate, GREEN).pack(side="left")
        self.button(controls, "SPEAK STATUS", self.speak_status).pack(side="left", padx=5)
        self.button(controls, "VOICE COMMAND", self.listen_once, AMBER).pack(side="left")
        self.button(controls, "PAUSE POLLING", self.toggle_poll, AMBER).pack(side="left", padx=5)
        self.label(controls, "LOCAL • READ-ONLY • SIMULATION LABELLED", MUTED, 7, True).pack(side="right")
        self.root.bind("<F11>", lambda _event: self.fullscreen())
        self.root.bind("<Escape>", lambda _event: self.root.attributes("-fullscreen", False))

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
            established = sum(str(row.get("State", "")).lower() in ("established", "5") for row in self.rows)
            self.conn_metric.configure(text=str(len(self.rows)))
            self.est_metric.configure(text=str(established))
            self.process_metric.configure(text=str(len({str(row.get("OwningProcess", "")) for row in self.rows})))
            self.current_alerts = assess_connections(self.rows, self.names)
            self.alert_metric.configure(text=str(len(self.current_alerts)))
            self.alerts.delete(0, tk.END)
            for item in self.current_alerts[:45]:
                color_tag = "!" if item["level"] != "INFO" else "i"
                self.alerts.insert(tk.END, f"{color_tag} {item['level']:<10} PID {item['pid']} {item['process']}  {item['remote']}")
            if not self.current_alerts:
                self.alerts.insert(tk.END, "No heuristic review hints in current snapshot.")
            self._render_insights()
            self._render_connections()
            self._draw_map()
            self._draw_workflow()
            self.status.configure(text="● LIVE / READ-ONLY", fg=GREEN)
        except Exception as exc:
            self.conn_metric.configure(text="N/A")
            self.status.configure(text="● TELEMETRY UNAVAILABLE", fg=AMBER)
            self.alerts.delete(0, tk.END)
            self.alerts.insert(tk.END, "Local telemetry unavailable: " + str(exc)[:130])
            self.alerts.insert(tk.END, "Unavailable data is not evidence of an attack.")
            self.insight_list.delete(0, tk.END)
            self.insight_list.insert(tk.END, "Check Windows / PowerShell availability.")
            self.insight_list.insert(tk.END, "No connections were changed.")

    def _render_connections(self):
        for item in self.table.get_children():
            self.table.delete(item)
        for row in self.rows[:120]:
            pid = str(row.get("OwningProcess", ""))
            self.table.insert("", "end", values=(
                f"{row.get('LocalAddress','')}:{row.get('LocalPort','')}",
                f"{row.get('RemoteAddress','')}:{row.get('RemotePort','')}",
                row.get("State", ""), pid, self.names.get(pid, "Unknown")))
        self.connection_detail.configure(text=f"{len(self.rows)} TCP entries • display capped at 120 rows")

    def _render_insights(self):
        self.insight_list.delete(0, tk.END)
        states = Counter(str(row.get("State", "")).lower() for row in self.rows)
        listen = sum(state in ("listen", "2") for state in states.elements())
        established = sum(state in ("established", "5") for state in states.elements())
        self.insight_list.insert(tk.END, f"• {established} established entries in current snapshot")
        self.insight_list.insert(tk.END, f"• {listen} listening entries; check exposed services as needed")
        if self.current_alerts:
            self.insight_list.insert(tk.END, f"• {len(self.current_alerts)} heuristic items need context review")
            self.insight_list.insert(tk.END, f"• Highest hint: {self.current_alerts[0]['level']} / score {self.current_alerts[0]['score']}")
        else:
            self.insight_list.insert(tk.END, "• No heuristic hints; this does not prove the device is clean")
        self.insight_list.insert(tk.END, "• No payloads captured; no settings changed")

    def _draw_map(self):
        c = self.map_canvas
        c.delete("all")
        w, h = max(c.winfo_width(), 250), max(c.winfo_height(), 135)
        # Schematic topology only. No destination geolocation is inferred.
        pts = [(w*.15, h*.43, "DEVICE"), (w*.50, h*.22, "GATEWAY"), (w*.83, h*.43, "REMOTE")]
        for a, b in ((pts[0], pts[1]), (pts[1], pts[2])):
            c.create_line(a[0], a[1], b[0], b[1], fill="#2b7187", width=2, dash=(3, 4))
        for x, y, name in pts:
            c.create_oval(x-17, y-17, x+17, y+17, fill="#12344a", outline=CYAN, width=2)
            c.create_oval(x-4, y-4, x+4, y+4, fill=GREEN, outline="")
            c.create_text(x, y+29, text=name, fill=TEXT, font=("Consolas", 7, "bold"))
        t = (self.animation_phase % 100) / 100
        a, b = pts[0], pts[1]
        x, y = a[0] + (b[0]-a[0])*t, a[1] + (b[1]-a[1])*t
        c.create_oval(x-4, y-4, x+4, y+4, fill=AMBER, outline="")
        c.create_text(w/2, h-7, text="SCHEMATIC / NOT GEOLOCATION", fill=AMBER, font=("Consolas", 7))

    def _draw_trend(self):
        c = self.trend_canvas
        c.delete("all")
        w, h = max(c.winfo_width(), 240), max(c.winfo_height(), 130)
        left, right, top, bottom = 24, w-8, 12, h-22
        for i in range(4):
            y = top + (bottom-top)*i/3
            c.create_line(left, y, right, y, fill=LINE, dash=(2, 4))
            c.create_text(13, y, text=str(100-i*30), fill=MUTED, font=("Consolas", 6))
        values = self.trend[:]
        values = values[1:] + [((self.animation_phase * 3) % 25) + 20]
        self.trend = values
        coords = []
        for i, value in enumerate(values):
            x = left + (right-left)*i/(len(values)-1)
            y = bottom - (bottom-top)*value/100
            coords.extend((x, y))
        c.create_line(*coords, fill=AMBER, width=2, smooth=True)
        c.create_text(w-39, h-8, text="SIMULATED", fill=AMBER, font=("Consolas", 6, "bold"))

    def _draw_workflow(self):
        c = self.workflow
        c.delete("all")
        w, h = max(c.winfo_width(), 280), max(c.winfo_height(), 60)
        labels = ["DETECT", "REVIEW", "APPROVE", "RESPOND"]
        for i, name in enumerate(labels):
            x = 32 + i*(w-64)/3
            c.create_oval(x-10, h/2-10, x+10, h/2+10, fill="#12344a", outline=CYAN if i < 2 else AMBER, width=2)
            c.create_text(x, h/2, text=str(i+1), fill=TEXT, font=("Consolas", 7, "bold"))
            c.create_text(x, h/2+20, text=name, fill=MUTED, font=("Consolas", 6, "bold"))
            if i < 3:
                nx = 32 + (i+1)*(w-64)/3
                c.create_line(x+11, h/2, nx-11, h/2, fill=LINE, width=2)

    def animate(self):
        self.animation_phase = (self.animation_phase + 2) % 100
        self._draw_trend()
        self._draw_map()
        self._draw_workflow()
        self.root.after(250, self.animate)

    def show_connection(self, _event=None):
        selected = self.table.selection()
        if selected:
            values = self.table.item(selected[0], "values")
            self.connection_detail.configure(text=f"{values[0]} → {values[1]} | {values[2]} | PID {values[3]} / {values[4]}")

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
            f"Reason: {item['reason']}\n\nThis is not proof of malicious activity. Verify expected behavior before taking action.",
        )

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

    def focus_processes(self):
        self.focus_connections()

    def simulate(self):
        self.timeline = getattr(self, "timeline", None)
        if self.timeline is None:
            messagebox.showinfo("Synthetic flow", "The simulated flow is shown in the topology diagram. No network traffic is generated.")
        else:
            self.timeline.delete(0, tk.END)
            for hop in simulated_hops():
                self.timeline.insert(tk.END, f"{hop['time']} {hop['packet']} {hop['source']} → {hop['destination']} [{hop['state']}]")

    def speak_status(self):
        if pyttsx3 is None:
            messagebox.showinfo("Optional voice", "Install optional speech with:\npython -m pip install pyttsx3")
            return
        def worker():
            try:
                engine = pyttsx3.init()
                engine.say(f"JARVIS online. {len(self.rows)} TCP entries. {len(self.current_alerts)} review hints. Read only mode.")
                engine.runAndWait()
            except Exception:
                pass
        threading.Thread(target=worker, daemon=True).start()

    def listen_once(self):
        if sr is None:
            messagebox.showinfo("Optional voice input", "Install optional voice input with:\npython -m pip install SpeechRecognition pyaudio")
            return
        self.status.configure(text="● LISTENING", fg=AMBER)
        def worker():
            try:
                recognizer = sr.Recognizer()
                with sr.Microphone() as source:
                    audio = recognizer.listen(source, timeout=4, phrase_time_limit=4)
                command = recognizer.recognize_google(audio).lower()
                self.root.after(0, lambda: self.handle_voice_command(command))
            except Exception:
                self.root.after(0, lambda: self.status.configure(text="● VOICE UNAVAILABLE", fg=AMBER))
        threading.Thread(target=worker, daemon=True).start()

    def handle_voice_command(self, command: str):
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
        elif "network" in command or "connection" in command:
            self.focus_connections()
        else:
            messagebox.showinfo("JARVIS command", "Try: refresh, status, simulate, fullscreen, pause, alerts, or connections.")

def main():
    if tk is None or ttk is None:
        raise RuntimeError("Tkinter is unavailable. Install Python with Tcl/Tk support.")
    root = tk.Tk()
    JarvisPlus(root)
    root.mainloop()


if __name__ == "__main__":
    main()
