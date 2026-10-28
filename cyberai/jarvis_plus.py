"""CyberAI JARVIS incident-management SOC desktop dashboard.

Run from the repository root:
    python -m cyberai.jarvis_plus

Live data: this Windows machine's TCP connection metadata and process names only.
The incident register, activity trend, and network topology are clearly synthetic
design/learning examples; this program does not capture packet payloads, connect
to WhatsApp, or perform network scans or automatic remediation.
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
    from tkinter import messagebox, ttk
except ImportError:  # Headless CI may still import the pure helper functions.
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


BG = "#050A10"
SIDEBAR = "#070F17"
PANEL = "#091820"
PANEL_ALT = "#0D242D"
EDGE = "#173740"
EDGE_BRIGHT = "#23616A"
TEAL = "#37E6D0"
CYAN = "#47CDE2"
GREEN = "#54F5C3"
AMBER = "#F2C66D"
RED = "#FF657A"
VIOLET = "#AA98FF"
WHITE = "#ECF7F8"
MUTED = "#91AEB4"
DIM = "#58777E"
FAINT = "#142D35"

TCP_QUERY = (
    "Get-NetTCPConnection -ErrorAction SilentlyContinue | "
    "Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,"
    "@{Name='State';Expression={$_.State.ToString()}},OwningProcess | "
    "ConvertTo-Json -Compress"
)
PROCESS_QUERY = "Get-Process | Select-Object Id,ProcessName | ConvertTo-Json -Compress"


def parse_json_rows(raw: str) -> list[dict[str, Any]]:
    """Parse PowerShell JSON which may contain one object or an array."""
    if not raw.strip():
        return []
    value = json.loads(raw)
    if isinstance(value, dict):
        value = [value]
    if not isinstance(value, list):
        raise ValueError("Expected a JSON object or array")
    return [row for row in value if isinstance(row, dict)]


def _state_name(value: Any) -> str:
    """Normalize Windows enum names and the common numeric TCP state values."""
    state = str(value or "").strip()
    numeric = {
        "1": "CLOSED", "2": "LISTEN", "3": "SYN_SENT", "4": "SYN_RECEIVED",
        "5": "ESTABLISHED", "6": "FIN_WAIT_1", "7": "FIN_WAIT_2",
        "8": "CLOSE_WAIT", "9": "CLOSING", "10": "LAST_ACK",
        "11": "TIME_WAIT", "12": "DELETE_TCB", "100": "UNKNOWN",
    }
    return numeric.get(state, state.replace(" ", "_").upper() or "UNKNOWN")


def assess_connections(
    rows: list[dict[str, Any]],
    process_names: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Create explainable triage hints, never a confirmed-malware verdict."""
    names = process_names or {}
    counts: Counter[str] = Counter(str(row.get("OwningProcess", "")) for row in rows)
    alerts: list[dict[str, Any]] = []
    for row in rows:
        local = str(row.get("LocalAddress", ""))
        remote = str(row.get("RemoteAddress", ""))
        state = _state_name(row.get("State", ""))
        pid = str(row.get("OwningProcess", ""))
        try:
            remote_port = int(row.get("RemotePort", 0) or 0)
        except (TypeError, ValueError):
            remote_port = 0
        score, reasons = 0, []
        # An established external connection is normal by itself; do not alert on it alone.
        if state == "LISTEN" and local in ("0.0.0.0", "::", "*"):
            score += 15
            reasons.append("Listening on a wildcard interface; verify the service is expected")
        if counts[pid] >= 80:
            score += 20
            reasons.append("This process owns many TCP entries; compare with its expected workload")
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
    names = {
        str(item.get("Id")): str(item.get("ProcessName", "Unknown"))
        for item in processes
    }
    return rows, names


def simulated_hops() -> list[dict[str, str]]:
    """Fictional message-flow steps; this helper performs no network I/O."""
    now = datetime.now().strftime("%H:%M:%S")
    return [
        {"time": now, "packet": "SIM-001", "source": "DEVICE", "destination": "LOCAL GATEWAY", "bytes": "384 B", "state": "OUTBOUND"},
        {"time": now, "packet": "SIM-002", "source": "LOCAL GATEWAY", "destination": "MESSAGING RELAY", "bytes": "1024 B", "state": "FORWARDED"},
        {"time": now, "packet": "SIM-003", "source": "MESSAGING RELAY", "destination": "RECIPIENT DEVICE", "bytes": "256 B", "state": "DELIVERED"},
    ]


def protocol_summary(rows: list[dict[str, Any]]) -> list[tuple[str, int]]:
    """Group current TCP entries by destination port; labels are approximate."""
    counts: Counter[str] = Counter()
    labels = {80: "HTTP", 443: "HTTPS/TLS", 53: "DNS/TCP", 22: "SSH", 3389: "RDP", 445: "SMB"}
    for row in rows:
        try:
            port = int(row.get("RemotePort", 0) or 0)
        except (TypeError, ValueError):
            port = 0
        counts[labels.get(port, "Other TCP")] += 1
    return counts.most_common(5)


DEMO_INCIDENTS = [
    ("INC-2847", "Ransomware Activity", "CRITICAL", "02:14 PM", "Sarah Chen"),
    ("INC-2848", "Unauthorized Access", "HIGH", "01:58 PM", "Alex Morgan"),
    ("INC-2849", "Data Exfiltration", "REVIEW", "01:32 PM", "David Lee"),
    ("INC-2850", "Endpoint Anomaly", "MEDIUM", "12:49 PM", "Priya Shah"),
]


class JarvisPlus:
    """Incident-management style SOC dashboard for local, read-only telemetry."""

    def __init__(self, root: Any):
        self.root = root
        self.root.title("CYBERAI JARVIS | Incident Management")
        self.root.geometry("1420x860")
        self.root.minsize(1050, 680)
        self.root.configure(bg=BG)
        self.rows: list[dict[str, Any]] = []
        self.names: dict[str, str] = {}
        self.current_alerts: list[dict[str, Any]] = []
        self.auto_refresh = True
        self.fullscreen_on = False
        self.trend_phase = 0
        self._build_styles()
        self._build_layout()
        self.refresh()
        self.simulate()
        self._animate()
        self._poll()
        self.root.bind("<F11>", lambda _e: self.toggle_fullscreen())
        self.root.bind("<Escape>", lambda _e: self.exit_fullscreen())

    def _label(self, parent: Any, text: str, color: str = WHITE, size: int = 9, bold: bool = False, **kwargs: Any):
        return tk.Label(
            parent, text=text, bg=parent.cget("bg"), fg=color,
            font=("Segoe UI", size, "bold" if bold else "normal"),
            anchor=kwargs.pop("anchor", "w"), **kwargs,
        )

    def _button(self, parent: Any, text: str, command: Any, color: str = TEAL):
        return tk.Button(
            parent, text=text, command=command, bg=PANEL_ALT, fg=color,
            activebackground="#15404A", activeforeground=WHITE,
            relief="flat", bd=0, padx=8, pady=5,
            font=("Segoe UI", 8, "bold"), cursor="hand2",
        )

    def _build_styles(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(
            "SOC.Treeview", background=PANEL, fieldbackground=PANEL,
            foreground=WHITE, rowheight=22, borderwidth=0,
            font=("Consolas", 8),
        )
        style.configure(
            "SOC.Treeview.Heading", background=PANEL_ALT, foreground=TEAL,
            font=("Segoe UI", 8, "bold"), relief="flat", padding=(4, 5),
        )
        style.map("SOC.Treeview", background=[("selected", "#17414A")], foreground=[("selected", WHITE)])

    def _panel(self, parent: Any, title: str, subtitle: str = "", accent: str = TEAL):
        outer = tk.Frame(parent, bg=EDGE, padx=1, pady=1)
        inner = tk.Frame(outer, bg=PANEL, padx=10, pady=8)
        inner.pack(fill="both", expand=True)
        header = tk.Frame(inner, bg=PANEL)
        header.pack(fill="x")
        self._label(header, title, accent, 9, True).pack(side="left", anchor="w")
        if subtitle:
            self._label(inner, subtitle, MUTED, 7).pack(anchor="w", pady=(3, 0))
        tk.Frame(inner, bg=EDGE, height=1).pack(fill="x", pady=(7, 5))
        return outer, inner

    def _metric_card(self, parent: Any, label: str, value: str, helper: str, accent: str):
        card = tk.Frame(parent, bg=PANEL, padx=10, pady=7, highlightthickness=1, highlightbackground=EDGE)
        tk.Frame(card, bg=accent, width=3).pack(side="left", fill="y", padx=(0, 9))
        body = tk.Frame(card, bg=PANEL)
        body.pack(side="left", fill="both", expand=True)
        self._label(body, label, MUTED, 7, True).pack(anchor="w")
        value_label = self._label(body, value, accent, 17, True)
        value_label.pack(anchor="w", pady=(2, 0))
        self._label(body, helper, DIM, 6).pack(anchor="w", pady=(1, 0))
        return card, value_label

    def _build_layout(self):
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        shell = tk.Frame(self.root, bg=BG)
        shell.grid(row=0, column=0, sticky="nsew")
        shell.grid_rowconfigure(0, weight=1)
        shell.grid_columnconfigure(1, weight=1)

        # Icon rail
        rail = tk.Frame(shell, bg=SIDEBAR, width=70, padx=8, pady=10)
        rail.grid(row=0, column=0, sticky="ns")
        rail.grid_propagate(False)
        brand = tk.Frame(rail, bg="#0D2A31", width=44, height=42, highlightthickness=1, highlightbackground=EDGE_BRIGHT)
        brand.pack(pady=(0, 20))
        brand.pack_propagate(False)
        self._label(brand, "▦", TEAL, 22, True, anchor="center").place(relx=.5, rely=.5, anchor="center")
        self.nav_buttons = {}
        for label, icon in [
            ("Overview", "▦"), ("Incidents", "△"), ("Network", "⌁"),
            ("Threats", "◉"), ("Assets", "▣"), ("Reports", "▤"), ("AI Insights", "✧"),
        ]:
            btn = tk.Button(
                rail, text=icon, command=lambda name=label: self._nav_action(name),
                bg="#10343C" if label == "Incidents" else SIDEBAR,
                fg=TEAL if label == "Incidents" else DIM,
                activebackground=PANEL_ALT, activeforeground=TEAL, relief="flat",
                bd=0, font=("Segoe UI Symbol", 14), width=3, pady=7, cursor="hand2",
            )
            btn.pack(fill="x", pady=3)
            self.nav_buttons[label] = btn
        tk.Frame(rail, bg=EDGE, height=1).pack(fill="x", pady=(15, 10), side="bottom")
        self._label(rail, "⚙", DIM, 15, anchor="center").pack(side="bottom", pady=(0, 10))

        main = tk.Frame(shell, bg=BG, padx=12, pady=8)
        main.grid(row=0, column=1, sticky="nsew")
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(3, weight=5)
        main.grid_rowconfigure(4, weight=5)

        # Toolbar with visual filters (not connected to external SOC data).
        toolbar = tk.Frame(main, bg=SIDEBAR, padx=8, pady=7, highlightthickness=1, highlightbackground=EDGE)
        toolbar.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        for value in ("TEAM: LOCAL ENDPOINT", "REGION: THIS DEVICE", "TIME: LAST 24 HOURS", "THREAT: REVIEW HINTS"):
            self._label(toolbar, value + "  ▾", WHITE, 7).pack(side="left", padx=(3, 7), pady=2)
        self._label(toolbar, "⌕  Search incidents / process…", DIM, 7).pack(side="left", padx=(10, 5))
        self.voice_chip = self._label(toolbar, "● VOICE OPTIONAL", MUTED, 7, True)
        self.voice_chip.pack(side="right", padx=(6, 3))
        self.status_label = self._label(toolbar, "● INITIALIZING", GREEN, 7, True)
        self.status_label.pack(side="right", padx=5)

        # Page heading
        heading = tk.Frame(main, bg=BG)
        heading.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        title_area = tk.Frame(heading, bg=BG)
        title_area.pack(side="left", fill="x", expand=True)
        self._label(title_area, "JARVIS  /  INCIDENT RESPONSE", TEAL, 7, True).pack(anchor="w")
        self._label(title_area, "Incidents Management", WHITE, 21, True).pack(anchor="w", pady=(2, 0))
        self._label(title_area, "Monitor, investigate, prioritize and resolve security events on this device.", MUTED, 8).pack(anchor="w", pady=(2, 0))
        actions = tk.Frame(heading, bg=BG)
        actions.pack(side="right", anchor="center")
        self._button(actions, "↻  REFRESH", self.refresh).pack(side="left", padx=3)
        self.pause_button = self._button(actions, "PAUSE", self.toggle_poll, AMBER)
        self.pause_button.pack(side="left", padx=3)
        self._button(actions, "FULLSCREEN  F11", self.toggle_fullscreen).pack(side="left", padx=3)

        # Four compact live telemetry cards.
        cards = tk.Frame(main, bg=BG)
        cards.grid(row=2, column=0, sticky="ew", pady=(0, 9))
        for i in range(4):
            cards.grid_columnconfigure(i, weight=1, uniform="kpi")
        self.conn_value = self.est_value = self.proc_value = self.alert_value = None
        metric_specs = [
            ("TCP CONNECTIONS", "—", "LIVE LOCAL TCP TABLE", CYAN),
            ("ESTABLISHED", "—", "CURRENT STATE COUNT", GREEN),
            ("PROCESSES SEEN", "—", "UNIQUE OWNER IDS", AMBER),
            ("REVIEW HINTS", "0", "EXPLAINABLE HEURISTICS", RED),
        ]
        for i, spec in enumerate(metric_specs):
            card, val = self._metric_card(cards, *spec)
            card.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 4, 0))
            if i == 0: self.conn_value = val
            elif i == 1: self.est_value = val
            elif i == 2: self.proc_value = val
            else: self.alert_value = val

        # Upper row: health gauge, topology, lifecycle.
        upper = tk.Frame(main, bg=BG)
        upper.grid(row=3, column=0, sticky="nsew", pady=(0, 8))
        upper.grid_columnconfigure(0, weight=3, uniform="upper")
        upper.grid_columnconfigure(1, weight=6, uniform="upper")
        upper.grid_columnconfigure(2, weight=4, uniform="upper")
        upper.grid_rowconfigure(0, weight=1)

        panel, self.health_panel = self._panel(upper, "INCIDENT HEALTH SCORE", "Local heuristic summary • not a security verdict")
        panel.grid(row=0, column=0, sticky="nsew", padx=(0, 4))
        self.health_canvas = tk.Canvas(self.health_panel, bg=PANEL, height=135, highlightthickness=0)
        self.health_canvas.pack(fill="x", expand=False, pady=(0, 3))
        self.local_summary = tk.Frame(self.health_panel, bg=PANEL)
        self.local_summary.pack(fill="both", expand=True)
        self.health_rows = {}
        for label in ("Active TCP entries", "Critical review hints", "Listening endpoints", "SLA / incidents"):
            row = tk.Frame(self.local_summary, bg=PANEL)
            row.pack(fill="x", pady=3)
            self._label(row, label, MUTED, 7).pack(side="left")
            value = self._label(row, "—", WHITE if label != "Critical review hints" else RED, 8, True)
            value.pack(side="right")
            self.health_rows[label] = value
        self._label(self.health_panel, "NO PAYLOAD CAPTURE  •  READ-ONLY", GREEN, 6, True).pack(anchor="w", pady=(5, 0))

        panel, topology_body = self._panel(upper, "NETWORK TOPOLOGY", "Schematic illustration • not live geolocation or packet routing")
        panel.grid(row=0, column=1, sticky="nsew", padx=4)
        legend = tk.Frame(topology_body, bg=PANEL)
        legend.pack(fill="x", pady=(0, 3))
        self._label(legend, "● REVIEW", RED, 6, True).pack(side="right", padx=(6, 0))
        self._label(legend, "● NORMAL", GREEN, 6, True).pack(side="right")
        self.topology_canvas = tk.Canvas(topology_body, bg=PANEL, height=125, highlightthickness=0)
        self.topology_canvas.pack(fill="x", expand=False)
        self.topology_canvas.bind("<Configure>", lambda _e: self._draw_topology())
        self._label(topology_body, "RECENT REVIEW HINTS", AMBER, 7, True).pack(anchor="w", pady=(3, 2))
        self.alert_rows_frame = tk.Frame(topology_body, bg=PANEL)
        self.alert_rows_frame.pack(fill="both", expand=True)

        panel, lifecycle = self._panel(upper, "INCIDENT LIFECYCLE", "SAMPLE CASE • INC-2847")
        panel.grid(row=0, column=2, sticky="nsew", padx=(4, 0))
        self.lifecycle_body = tk.Frame(lifecycle, bg=PANEL)
        self.lifecycle_body.pack(fill="both", expand=True)
        for i, (stage, detail, status, color) in enumerate([
            ("Detection", "Alert observed and logged", "RESOLVED", GREEN),
            ("Investigation started", "Analyst review in progress", "MONITORING", AMBER),
            ("Threat confirmed", "Needs evidence validation", "REVIEW", RED),
            ("Containment initiated", "Approval required before action", "PENDING", AMBER),
            ("Recovery in progress", "No automatic remediation", "PENDING", CYAN),
            ("Resolution", "Await analyst confirmation", "PENDING", MUTED),
        ]):
            row = tk.Frame(self.lifecycle_body, bg=PANEL)
            row.pack(fill="x", pady=4)
            self._label(row, f"{i+1:02d}", color, 7, True).pack(side="left", padx=(0, 8))
            center = tk.Frame(row, bg=PANEL)
            center.pack(side="left", fill="x", expand=True)
            self._label(center, stage, WHITE, 7, True).pack(anchor="w")
            self._label(center, detail, MUTED, 6).pack(anchor="w", pady=(1, 0))
            self._label(row, status, color, 6, True).pack(side="right", padx=(3, 0))

        # Lower row: analyst note, incident table, sample trend.
        lower = tk.Frame(main, bg=BG)
        lower.grid(row=4, column=0, sticky="nsew")
        lower.grid_columnconfigure(0, weight=3, uniform="lower")
        lower.grid_columnconfigure(1, weight=6, uniform="lower")
        lower.grid_columnconfigure(2, weight=4, uniform="lower")
        lower.grid_rowconfigure(0, weight=1)

        panel, investigation = self._panel(lower, "AI INVESTIGATION", "Rule-based local guidance • advisory only")
        panel.grid(row=0, column=0, sticky="nsew", padx=(0, 4))
        self._label(investigation, "✦  JARVIS ANALYST NOTE", GREEN, 8, True).pack(anchor="w", pady=(2, 5))
        self.insight_text = tk.Text(investigation, height=4, wrap="word", bg=PANEL, fg=WHITE,
                                    relief="flat", bd=0, font=("Segoe UI", 8), insertbackground=TEAL)
        self.insight_text.pack(fill="x", expand=False)
        self.insight_text.insert("1.0", "Waiting for local connection metadata. Review process, endpoint, and expected workload before escalating.")
        self.insight_text.configure(state="disabled")
        tk.Frame(investigation, bg=EDGE, height=1).pack(fill="x", pady=7)
        self._label(investigation, "THREAT ATTRIBUTION", WHITE, 8, True).pack(anchor="w")
        self._label(investigation, "Illustrative mix • not a live threat feed", MUTED, 6).pack(anchor="w", pady=(2, 4))
        attribution = tk.Canvas(investigation, bg=PANEL, height=92, highlightthickness=0)
        attribution.pack(fill="x", expand=False)
        self.attribution_canvas = attribution
        self._draw_attribution()

        center = tk.Frame(lower, bg=BG)
        center.grid(row=0, column=1, sticky="nsew", padx=4)
        center.grid_rowconfigure(1, weight=1)
        center.grid_columnconfigure(0, weight=1)
        incident_metrics = tk.Frame(center, bg=BG)
        incident_metrics.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        for i, (label, value, color) in enumerate([
            ("OPEN CASES", "38", TEAL), ("CRITICAL", "5", RED),
            ("RESOLVED TODAY", "127", GREEN), ("MEAN RESPONSE", "12m", AMBER),
        ]):
            incident_metrics.grid_columnconfigure(i, weight=1, uniform="incidents")
            card, _val = self._metric_card(incident_metrics, label, value, "DEMO INCIDENT DATA", color)
            card.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 3, 0))

        panel, threat = self._panel(center, "GLOBAL THREAT READER", "Demo incident register + live local TCP table • switch views")
        panel.grid(row=1, column=0, sticky="nsew")
        switchbar = tk.Frame(threat, bg=PANEL)
        switchbar.pack(fill="x", pady=(0, 4))
        self._button(switchbar, "DEMO INCIDENTS", lambda: self._show_data_view("incidents"), TEAL).pack(side="left", padx=(0, 4))
        self._button(switchbar, "LIVE TCP CONNECTIONS", lambda: self._show_data_view("connections"), GREEN).pack(side="left")
        self.view_stack = tk.Frame(threat, bg=PANEL)
        self.view_stack.pack(fill="both", expand=True)
        self.incidents_view = tk.Frame(self.view_stack, bg=PANEL)
        self.connections_view = tk.Frame(self.view_stack, bg=PANEL)
        for view in (self.incidents_view, self.connections_view):
            view.place(relx=0, rely=0, relwidth=1, relheight=1)
        cols = ("owner", "id", "type", "severity", "time")
        self.incident_table = ttk.Treeview(self.incidents_view, columns=cols, show="headings", height=5, style="SOC.Treeview")
        headings = [("owner", "ASSIGNED TO", 90), ("id", "INCIDENT ID", 80), ("type", "TYPE", 130), ("severity", "SEVERITY", 70), ("time", "TIME", 65)]
        for col, label, width in headings:
            self.incident_table.heading(col, text=label)
            self.incident_table.column(col, width=width, minwidth=45, anchor="w", stretch=True)
        incident_scroll = ttk.Scrollbar(self.incidents_view, orient="vertical", command=self.incident_table.yview)
        self.incident_table.configure(yscrollcommand=incident_scroll.set)
        self.incident_table.pack(side="left", fill="both", expand=True, pady=(3, 0))
        incident_scroll.pack(side="right", fill="y", pady=(3, 0))
        for item in DEMO_INCIDENTS:
            self.incident_table.insert("", "end", values=item, tags=(item[2],))
        self.incident_table.tag_configure("CRITICAL", foreground=RED)
        self.incident_table.tag_configure("HIGH", foreground=AMBER)
        self.incident_table.tag_configure("REVIEW", foreground=TEAL)
        self.incident_table.tag_configure("MEDIUM", foreground=VIOLET)
        live_cols = ("local", "remote", "state", "pid", "process")
        self.connection_table = ttk.Treeview(self.connections_view, columns=live_cols, show="headings", height=5, style="SOC.Treeview")
        for col, label, width in [
            ("local", "LOCAL ENDPOINT", 125), ("remote", "REMOTE ENDPOINT", 125),
            ("state", "STATE", 75), ("pid", "PID", 50), ("process", "PROCESS", 85),
        ]:
            self.connection_table.heading(col, text=label)
            self.connection_table.column(col, width=width, minwidth=40, anchor="w", stretch=True)
        live_scroll = ttk.Scrollbar(self.connections_view, orient="vertical", command=self.connection_table.yview)
        self.connection_table.configure(yscrollcommand=live_scroll.set)
        self.connection_table.pack(side="left", fill="both", expand=True, pady=(3, 0))
        live_scroll.pack(side="right", fill="y", pady=(3, 0))
        self.connection_table.bind("<<TreeviewSelect>>", self.show_connection)
        self._show_data_view("incidents")

        panel, trend = self._panel(lower, "INCIDENT VOLUME TREND", "Sample counts • replace with incident telemetry")
        panel.grid(row=0, column=2, sticky="nsew", padx=(4, 0))
        self._label(trend, "● New      ● Resolved      ● Escalated", MUTED, 6).pack(anchor="w", pady=(0, 2))
        self.trend_canvas = tk.Canvas(trend, bg=PANEL, height=145, highlightthickness=0)
        self.trend_canvas.pack(fill="both", expand=True)
        self.trend_canvas.bind("<Configure>", lambda _e: self._draw_trend())
        footer = tk.Frame(main, bg=BG)
        footer.grid(row=5, column=0, sticky="ew", pady=(6, 0))
        tk.Frame(footer, bg=EDGE, height=1).pack(fill="x", pady=(0, 5))
        self._label(footer, "● LOCAL / READ-ONLY     •     DESIGN CASES ARE SYNTHETIC     •     NO PAYLOAD CAPTURE OR AUTOMATIC RESPONSE",
                    MUTED, 6, True).pack(side="left")
        self.clock = self._label(footer, "", TEAL, 7, True)
        self.clock.pack(side="right")

        # Incident sidebar and center row are illustrative; connection table is live.
        self.root.bind("<Control-r>", lambda _e: self.refresh())

    def _nav_action(self, name: str):
        if name in ("Overview", "Incidents"):
            self._show_data_view("incidents")
            self.refresh()
        elif name in ("Network", "Assets"):
            self._show_data_view("connections")
            self.focus_connections()
        elif name in ("Threats", "AI Insights"):
            self.focus_alerts()
        elif name == "Reports":
            self.speak_status()
        else:
            messagebox.showinfo("JARVIS", "This screen is a read-only local monitoring preview. No external threat feed is configured.")

    def _show_data_view(self, name: str):
        if name == "connections":
            self.connections_view.tkraise()
            self.status_label.configure(text="● LOCAL TCP VIEW", fg=GREEN)
        else:
            self.incidents_view.tkraise()
            self.status_label.configure(text="● INCIDENTS: DEMO DATA", fg=AMBER)

    def _draw_health(self):
        c = self.health_canvas
        c.delete("all")
        w = max(c.winfo_width(), 230)
        h = max(c.winfo_height(), 130)
        cx, cy = w / 2, 70
        r = min(62, w * 0.28)
        for i in range(36):
            start = 180 - i * 180 / 36
            color = RED if i < 6 else AMBER if i < 12 else TEAL if i < 31 else FAINT
            c.create_arc(cx-r, cy-r, cx+r, cy+r, start=start, extent=-4,
                         style=tk.ARC, outline=color, width=5)
        score = max(0, 100 - min(45, len(self.current_alerts) * 5))
        c.create_text(cx, cy-4, text=str(score), fill=WHITE, font=("Segoe UI", 24, "bold"))
        c.create_text(cx+24, cy+4, text="/100", fill=MUTED, font=("Segoe UI", 7))
        c.create_text(cx, cy+23, text="HEURISTIC POSTURE", fill=GREEN, font=("Segoe UI", 7, "bold"))
        c.create_text(cx, h-8, text="NOT A SECURITY VERDICT", fill=DIM, font=("Segoe UI", 6))

    def _draw_topology(self):
        c = self.topology_canvas
        if not c.winfo_exists():
            return
        c.delete("all")
        w, h = max(c.winfo_width(), 320), max(c.winfo_height(), 120)
        pts = {
            "DEVICE": (w*.10, h*.56, TEAL),
            "FIREWALL": (w*.29, h*.42, GREEN),
            "SWITCH": (w*.48, h*.56, TEAL),
            "WS-001": (w*.68, h*.24, CYAN),
            "DB-PROD": (w*.70, h*.70, AMBER),
            "CLOUD": (w*.89, h*.42, GREEN),
            "FIN-SRV": (w*.48, h*.73, RED),
        }
        def path(a: str, b: str, color: str, bend: float = 0):
            x1,y1,_=pts[a]; x2,y2,_=pts[b]
            mid=(x1+x2)/2
            c.create_line(x1,y1,mid,y1,mid,y2,x2,y2,fill=color,width=2,smooth=False)
        path("DEVICE","FIREWALL",TEAL)
        path("FIREWALL","SWITCH",GREEN)
        path("SWITCH","WS-001",TEAL)
        path("WS-001","CLOUD",TEAL)
        path("SWITCH","FIN-SRV",RED)
        path("FIN-SRV","DB-PROD",RED)
        for name,(x,y,color) in pts.items():
            r=11
            c.create_oval(x-r-4,y-r-4,x+r+4,y+r+4,fill="#0A252D",outline=EDGE_BRIGHT,width=1)
            c.create_oval(x-r,y-r,x+r,y+r,fill=PANEL_ALT,outline=color,width=2)
            c.create_oval(x-4,y-4,x+4,y+4,fill=color,outline="")
            c.create_text(x,y+r+10,text=name,fill=WHITE,font=("Consolas",7,"bold"))
        c.create_text(w-8,h-5,text="SCHEMATIC / NO GEOLOCATION",fill=DIM,font=("Consolas",6),anchor="e")

    def _draw_attribution(self):
        c = self.attribution_canvas
        if not c.winfo_exists():
            return
        c.delete("all")
        w=max(c.winfo_width(),250)
        items=[("Malware",.25,RED),("Credential",.19,AMBER),("Network",.31,TEAL),("Other",.25,VIOLET)]
        for i,(label,ratio,color) in enumerate(items):
            y=9+i*21
            c.create_text(0,y,text=label,fill=MUTED,font=("Segoe UI",7),anchor="nw")
            c.create_rectangle(78,y+3,w-32,y+12,fill=FAINT,outline="")
            c.create_rectangle(78,y+3,78+(w-110)*ratio,y+12,fill=color,outline="")
            c.create_text(w-2,y,text=f"{round(ratio*100)}%",fill=color,font=("Consolas",7,"bold"),anchor="ne")

    def _draw_trend(self):
        c = self.trend_canvas
        if not c.winfo_exists():
            return
        c.delete("all")
        w,h=max(c.winfo_width(),290),max(c.winfo_height(),130)
        left,right,top,bottom=24,w-10,12,h-23
        for i in range(4):
            y=top+(bottom-top)*i/3
            c.create_line(left,y,right,y,fill=EDGE,dash=(2,4))
        series=[
            ([26,32,29,40,37,47,43,50,45,57,51,61,55,66],TEAL),
            ([18,23,21,27,26,34,31,36,33,40,36,44,41,48],GREEN),
            ([8,10,9,15,12,17,16,19,15,22,19,24,21,27],AMBER),
        ]
        for vals,color in series:
            pts=[]
            for i,val in enumerate(vals):
                x=left+i*(right-left)/(len(vals)-1)
                y=bottom-(val/80)*(bottom-top)
                pts.extend((x,y))
            c.create_line(*pts,fill=color,width=2,smooth=True)
        c.create_text(left,bottom+10,text="00:00",fill=DIM,font=("Consolas",6),anchor="w")
        c.create_text((left+right)/2,bottom+10,text="12:00",fill=DIM,font=("Consolas",6),anchor="center")
        c.create_text(right,bottom+10,text="NOW",fill=DIM,font=("Consolas",6),anchor="e")
        c.create_text(right,top+3,text="SAMPLE TREND",fill=AMBER,font=("Consolas",6,"bold"),anchor="e")

    def _render_connections(self):
        for item in self.connection_table.get_children():
            self.connection_table.delete(item)
        for row in self.rows[:180]:
            pid=str(row.get("OwningProcess",""))
            state=_state_name(row.get("State",""))
            values=(
                f"{row.get('LocalAddress','')}:{row.get('LocalPort','')}",
                f"{row.get('RemoteAddress','')}:{row.get('RemotePort','')}",
                state,pid,self.names.get(pid,"Unknown"),
            )
            tag="LISTEN" if state=="LISTEN" else "ESTABLISHED" if state=="ESTABLISHED" else "OTHER"
            self.connection_table.insert("","end",values=values,tags=(tag,))
        self.connection_table.tag_configure("LISTEN",foreground=AMBER)
        self.connection_table.tag_configure("ESTABLISHED",foreground=GREEN)
        self.connection_table.tag_configure("OTHER",foreground=WHITE)

    def _build_connection_view(self):
        # Kept as a separate method for testable and maintainable UI evolution.
        return None

    def refresh(self):
        try:
            self.rows,self.names=get_live_data()
            self.current_alerts=assess_connections(self.rows,self.names)
            established=sum(_state_name(r.get("State",""))=="ESTABLISHED" for r in self.rows)
            listening=sum(_state_name(r.get("State",""))=="LISTEN" for r in self.rows)
            self.conn_value.configure(text=str(len(self.rows)))
            self.est_value.configure(text=str(established))
            self.proc_value.configure(text=str(len({str(r.get("OwningProcess","")) for r in self.rows})))
            self.alert_value.configure(text=str(len(self.current_alerts)))
            self.health_rows["Active TCP entries"].configure(text=str(len(self.rows)))
            high=sum(a["level"]=="HIGH REVIEW" for a in self.current_alerts)
            self.health_rows["Critical review hints"].configure(text=str(high))
            self.health_rows["Listening endpoints"].configure(text=str(listening))
            self.health_rows["SLA / incidents"].configure(text="DEMO")
            self._draw_health()
            self._render_connections()
            self._render_alerts()
            if self.current_alerts:
                lead=self.current_alerts[0]
                msg=f"{len(self.rows)} TCP entries were read locally. {len(self.current_alerts)} heuristic review hints are available. Highest hint: {lead['level']} for {lead['process']} (PID {lead['pid']}). Verify local process and destination context; no action was taken."
            else:
                msg=f"{len(self.rows)} TCP entries were read locally. No current heuristics matched. This is not proof that the device is threat-free."
            self._set_insight(msg)
            self.status_label.configure(text="● LOCAL TELEMETRY AVAILABLE",fg=GREEN)
        except Exception as exc:
            self.rows=[]
            self.current_alerts=[]
            self.conn_value.configure(text="N/A")
            self.est_value.configure(text="N/A")
            self.proc_value.configure(text="N/A")
            self.alert_value.configure(text="N/A")
            self.status_label.configure(text="● TELEMETRY UNAVAILABLE",fg=AMBER)
            self._render_alerts(error=str(exc))
            self._set_insight("Local telemetry is unavailable. Verify that this is Windows and PowerShell is available. Unavailable data is not evidence of an attack; no connections or settings were changed.")
        self._draw_health()

    def _render_alerts(self,error: str | None = None):
        for child in self.alert_rows_frame.winfo_children():
            child.destroy()
        if error:
            self._label(self.alert_rows_frame,"LOCAL TELEMETRY UNAVAILABLE",AMBER,8,True).pack(anchor="w",pady=4)
            self._label(self.alert_rows_frame,error[:135],MUTED,7).pack(anchor="w")
            return
        if not self.current_alerts:
            self._label(self.alert_rows_frame,"No heuristic review hints in this snapshot.",GREEN,7).pack(anchor="w",pady=3)
            self._label(self.alert_rows_frame,"Normal connections are not alerts by themselves.",MUTED,6).pack(anchor="w")
            return
        for item in self.current_alerts[:5]:
            color=RED if item["level"]=="HIGH REVIEW" else AMBER if item["level"]=="REVIEW" else TEAL
            row=tk.Frame(self.alert_rows_frame,bg=PANEL)
            row.pack(fill="x",pady=3)
            self._label(row,item["level"],color,6,True,width=10).pack(side="left",anchor="n")
            detail=tk.Frame(row,bg=PANEL)
            detail.pack(side="left",fill="x",expand=True)
            self._label(detail,f"{item['process']}  •  PID {item['pid']}",WHITE,7,True).pack(anchor="w")
            self._label(detail,f"{item['local']}  →  {item['remote']}",MUTED,6).pack(anchor="w")
            row.bind("<Button-1>",lambda _e, alert=item:self._show_alert_detail(alert))

    def _set_insight(self,text: str):
        self.insight_text.configure(state="normal")
        self.insight_text.delete("1.0",tk.END)
        self.insight_text.insert("1.0",text)
        self.insight_text.configure(state="disabled")

    def _show_alert_detail(self,item:dict[str,Any]):
        messagebox.showinfo(
            "Explainable review hint",
            f"Level: {item['level']} | Score: {item['score']}/100\n"
            f"Process: {item['process']} (PID {item['pid']})\n"
            f"Local endpoint: {item['local']}\nRemote endpoint: {item['remote']}\n"
            f"State: {item['state']}\n\nReason: {item['reason']}\n\n"
            "This hint is not proof of malicious activity. Verify the process, destination, and expected behavior.",
        )

    def show_alert(self,_event=None):
        selected=self.alerts_list.curselection()
        if selected and selected[0]<len(self.current_alerts):
            self._show_alert_detail(self.current_alerts[selected[0]])

    def focus_alerts(self):
        if self.current_alerts:
            self._show_alert_detail(self.current_alerts[0])
        else:
            messagebox.showinfo("Review hints","No heuristic review hints in the current local snapshot. This does not prove the device is threat-free.")

    def focus_connections(self):
        children=self.connection_table.get_children()
        if children:
            self.connection_table.selection_set(children[0])
            self.connection_table.focus(children[0])
            self.connection_table.see(children[0])

    def show_connection(self,_event=None):
        selected=self.connection_table.selection()
        if selected:
            values=self.connection_table.item(selected[0],"values")
            messagebox.showinfo("Local TCP connection",
                f"Local: {values[0]}\nRemote: {values[1]}\nState: {values[2]}\nPID: {values[3]}\nProcess: {values[4]}\n\nMetadata only; payload is not captured.")

    def simulate(self):
        if not hasattr(self,"simulation_list"):
            return
        self.simulation_list.delete(0,tk.END)
        for hop in simulated_hops():
            self.simulation_list.insert(tk.END,
                f"{hop['time']}  {hop['packet']}  {hop['source']} -> {hop['destination']} [{hop['state']}]")

    def toggle_poll(self):
        self.auto_refresh=not self.auto_refresh
        self.pause_button.configure(text="PAUSE" if self.auto_refresh else "RESUME")
        self.status_label.configure(
            text="● LOCAL TELEMETRY AVAILABLE" if self.auto_refresh else "● AUTO-REFRESH PAUSED",
            fg=GREEN if self.auto_refresh else AMBER,
        )

    def toggle_fullscreen(self):
        self.fullscreen_on=not self.fullscreen_on
        self.root.attributes("-fullscreen",self.fullscreen_on)

    def exit_fullscreen(self):
        self.fullscreen_on=False
        self.root.attributes("-fullscreen",False)

    def _poll(self):
        self.clock.configure(text=datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
        if self.auto_refresh:
            self.refresh()
        self.root.after(10000,self._poll)

    def speak_status(self):
        if pyttsx3 is None:
            messagebox.showinfo("Optional voice","Voice output is optional. Install with: python -m pip install pyttsx3")
            return
        def worker():
            try:
                engine=pyttsx3.init()
                engine.say(f"JARVIS online. {len(self.rows)} local TCP entries and {len(self.current_alerts)} heuristic review hints. Read only mode.")
                engine.runAndWait()
            except Exception:
                pass
        threading.Thread(target=worker,daemon=True).start()

    def listen_once(self):
        if sr is None:
            messagebox.showinfo("Optional voice input","Voice input is optional. Install with: python -m pip install SpeechRecognition pyaudio")
            return
        self.voice_chip.configure(text="● LISTENING",fg=AMBER)
        def worker():
            try:
                recognizer=sr.Recognizer()
                with sr.Microphone() as source:
                    audio=recognizer.listen(source,timeout=4,phrase_time_limit=4)
                # Optional online recognizer can transmit audio to Google's service.
                command=recognizer.recognize_google(audio).lower()
                self.root.after(0,lambda:self.handle_voice_command(command))
            except Exception:
                self.root.after(0,lambda:self.voice_chip.configure(text="● VOICE UNAVAILABLE",fg=AMBER))
        threading.Thread(target=worker,daemon=True).start()

    def handle_voice_command(self,command:str):
        self.voice_chip.configure(text="● VOICE RECEIVED",fg=GREEN)
        if "refresh" in command or "status" in command:
            self.refresh()
            if "status" in command:
                self.speak_status()
        elif "simulate" in command or "message" in command:
            self.simulate()
        elif "fullscreen" in command:
            self.toggle_fullscreen()
        elif "pause" in command or "resume" in command:
            self.toggle_poll()
        elif "alert" in command or "incident" in command:
            self.focus_alerts()
        elif "network" in command or "connection" in command:
            self.focus_connections()
        else:
            messagebox.showinfo("JARVIS voice command","Try: refresh, status, simulate, fullscreen, pause, alerts, or connections.")

    def _animate(self):
        self.trend_phase=(self.trend_phase+1)%100
        self._draw_topology()
        self._draw_trend()
        self._draw_health()
        self.root.after(400,self._animate)


def main():
    if tk is None or ttk is None:
        raise RuntimeError("Tkinter is unavailable. Install Python with Tcl/Tk support.")
    root = tk.Tk()
    JarvisPlus(root)
    root.mainloop()


if __name__ == "__main__":
    main()
