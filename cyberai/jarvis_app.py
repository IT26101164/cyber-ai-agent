"""JARVIS-style local network dashboard for CyberAI.

The live panel shows Windows TCP connection metadata only. The messaging lab is
synthetic; it never connects to WhatsApp or sends messages.
Run with: python -m cyberai.jarvis_app
"""
from __future__ import annotations

import json
import platform
import random
import subprocess
import tkinter as tk
from datetime import datetime
from tkinter import ttk
from typing import Any

BG = "#07111f"
PANEL = "#0d1b2a"
PANEL_ALT = "#102338"
CYAN = "#4de4ff"
GREEN = "#4dffb5"
AMBER = "#ffc857"
RED = "#ff657a"
TEXT = "#e8f4ff"
MUTED = "#8ca7bd"

POWERSHELL_QUERY = (
    "Get-NetTCPConnection -ErrorAction SilentlyContinue | "
    "Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | "
    "ConvertTo-Json -Compress"
)


def parse_connections_json(raw: str) -> list[dict[str, Any]]:
    """Normalize PowerShell JSON output (single object or array) to safe rows."""
    if not raw.strip():
        return []
    parsed = json.loads(raw)
    if isinstance(parsed, dict):
        parsed = [parsed]
    if not isinstance(parsed, list):
        raise ValueError("Unexpected connection data format")
    rows: list[dict[str, Any]] = []
    allowed = ("LocalAddress", "LocalPort", "RemoteAddress", "RemotePort", "State", "OwningProcess")
    for item in parsed:
        if not isinstance(item, dict):
            continue
        row = {key: item.get(key, "") for key in allowed}
        rows.append(row)
    return rows


def format_bytes(value: int) -> str:
    """Format a byte count for display."""
    amount = float(max(0, value))
    for unit in ("B", "KB", "MB", "GB"):
        if amount < 1024 or unit == "GB":
            return f"{amount:.0f} {unit}" if unit == "B" else f"{amount:.1f} {unit}"
        amount /= 1024
    return f"{amount:.1f} GB"


def make_simulated_events() -> list[dict[str, str]]:
    """Return fictional messaging metadata; no network I/O occurs."""
    now = datetime.now().strftime("%H:%M:%S")
    route = [
        ("DEVICE", "LOCAL GATEWAY", "TLS-like encrypted transport (SIMULATED)", "OUTBOUND"),
        ("LOCAL GATEWAY", "MESSAGING RELAY", "Encrypted payload placeholder (SIMULATED)", "FORWARDED"),
        ("MESSAGING RELAY", "RECIPIENT DEVICE", "Encrypted payload placeholder (SIMULATED)", "DELIVERED"),
    ]
    events = []
    for index, (source, destination, detail, state) in enumerate(route, start=1):
        events.append({
            "time": now,
            "source": source,
            "destination": destination,
            "detail": detail,
            "state": state,
            "bytes": str(random.choice((128, 256, 384, 512, 768, 1024))),
            "packet": f"SIM-{index:03d}",
        })
    return events


def get_live_connections() -> list[dict[str, Any]]:
    """Read current Windows TCP connection metadata using a fixed PowerShell query."""
    if platform.system() != "Windows":
        raise OSError("Live connection view currently requires Windows.")
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", POWERSHELL_QUERY],
        capture_output=True,
        text=True,
        timeout=8,
        check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if completed.returncode != 0:
        message = completed.stderr.strip() or "PowerShell could not read TCP connection metadata."
        raise RuntimeError(message[:300])
    return parse_connections_json(completed.stdout)


class JarvisDashboard:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("CYBERAI // JARVIS NETWORK INTELLIGENCE")
        self.root.geometry("1220x800")
        self.root.minsize(980, 680)
        self.root.configure(bg=BG)
        self.live_rows: list[dict[str, Any]] = []
        self.sim_events: list[dict[str, str]] = []
        self.live_enabled = True
        self._configure_style()
        self._build_ui()
        self._draw_network()
        self.refresh_connections()
        self.root.after(5000, self._poll)

    def _configure_style(self) -> None:
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background=PANEL, fieldbackground=PANEL, foreground=TEXT,
                        rowheight=27, borderwidth=0, font=("Consolas", 9))
        style.configure("Treeview.Heading", background=PANEL_ALT, foreground=CYAN,
                        font=("Consolas", 9, "bold"), relief="flat")
        style.map("Treeview", background=[("selected", "#17445b")], foreground=[("selected", TEXT)])
        style.configure("TScrollbar", background=PANEL_ALT, troughcolor=BG, bordercolor=BG)

    def _label(self, parent: tk.Widget, text: str, *, size: int = 10,
               color: str = TEXT, bold: bool = False) -> tk.Label:
        return tk.Label(parent, text=text, bg=parent.cget("bg"), fg=color,
                        font=("Consolas", size, "bold" if bold else "normal"))

    def _button(self, parent: tk.Widget, text: str, command: Any,
                color: str = CYAN) -> tk.Button:
        return tk.Button(parent, text=text, command=command, bg=PANEL_ALT, fg=color,
                         activebackground="#17445b", activeforeground=TEXT,
                         relief="flat", bd=0, padx=13, pady=8,
                         font=("Consolas", 9, "bold"), cursor="hand2")

    def _build_ui(self) -> None:
        header = tk.Frame(self.root, bg=BG, padx=22, pady=16)
        header.pack(fill="x")
        tk.Label(header, text="C Y B E R A I  /  J A R V I S", bg=BG, fg=CYAN,
                 font=("Consolas", 20, "bold")).pack(side="left")
        self.clock = self._label(header, "INITIALIZING...", size=10, color=GREEN, bold=True)
        self.clock.pack(side="right")
        self._tick_clock()

        cards = tk.Frame(self.root, bg=BG, padx=18)
        cards.pack(fill="x")
        self.connection_value = self._metric_card(cards, "TCP CONNECTIONS", "—", CYAN)
        self.sim_value = self._metric_card(cards, "SIM LAB EVENTS", "0", GREEN)
        self.mode_value = self._metric_card(cards, "MONITOR MODE", "LOCAL / READ-ONLY", AMBER)

        content = tk.Frame(self.root, bg=BG, padx=18, pady=14)
        content.pack(fill="both", expand=True)
        left = tk.Frame(content, bg=PANEL, padx=12, pady=12)
        left.pack(side="left", fill="both", expand=True, padx=(0, 8))
        right = tk.Frame(content, bg=PANEL, padx=12, pady=12, width=390)
        right.pack(side="right", fill="both", expand=True, padx=(8, 0))
        right.pack_propagate(False)

        self._label(left, "01 / LIVE CONNECTION TELEMETRY", size=11, color=CYAN, bold=True).pack(anchor="w")
        self._label(left, "Windows TCP metadata • no payload capture", size=9, color=MUTED).pack(anchor="w", pady=(4, 10))
        cols = ("local", "remote", "state", "pid")
        self.connections = ttk.Treeview(left, columns=cols, show="headings", height=15)
        for col, title, width in (
            ("local", "LOCAL ENDPOINT", 175), ("remote", "REMOTE ENDPOINT", 175),
            ("state", "STATE", 100), ("pid", "PID", 60),
        ):
            self.connections.heading(col, text=title)
            self.connections.column(col, width=width, anchor="w")
        self.connections.pack(fill="both", expand=True)
        self.live_status = self._label(left, "Waiting for first read...", size=9, color=MUTED)
        self.live_status.pack(anchor="w", pady=(8, 0))
        controls = tk.Frame(left, bg=PANEL)
        controls.pack(fill="x", pady=(10, 0))
        self._button(controls, "↻ REFRESH", self.refresh_connections).pack(side="left")
        self._button(controls, "PAUSE POLL", self.toggle_poll, AMBER).pack(side="left", padx=8)

        self._label(right, "02 / MESSAGING PACKET-FLOW LAB", size=11, color=GREEN, bold=True).pack(anchor="w")
        self._label(right, "Synthetic demo only • no WhatsApp connection", size=9, color=MUTED).pack(anchor="w", pady=(4, 10))
        self.graph = tk.Canvas(right, bg="#081522", height=205, highlightthickness=1,
                               highlightbackground="#1d3b50")
        self.graph.pack(fill="x")
        actions = tk.Frame(right, bg=PANEL)
        actions.pack(fill="x", pady=10)
        self._button(actions, "▶ RUN SIMULATION", self.run_simulation, GREEN).pack(side="left")
        self._button(actions, "CLEAR", self.clear_simulation, AMBER).pack(side="left", padx=8)
        self._label(right, "EVENT TIMELINE", size=9, color=CYAN, bold=True).pack(anchor="w", pady=(4, 5))
        self.timeline = tk.Listbox(right, bg="#081522", fg=TEXT, selectbackground="#17445b",
                                   font=("Consolas", 9), relief="flat", height=8,
                                   highlightthickness=0)
        self.timeline.pack(fill="both", expand=True)
        footer = tk.Frame(self.root, bg="#091725", padx=20, pady=9)
        footer.pack(fill="x")
        tk.Label(footer, text="DEFENSIVE MODE  •  LIVE VIEW = CONNECTION METADATA  •  SIMULATION = FICTIONAL",
                 bg="#091725", fg=MUTED, font=("Consolas", 9)).pack(side="left")
        self._label(footer, "NO ACCOUNT ACCESS / NO PACKET PAYLOADS", size=9, color=AMBER).pack(side="right")

    def _metric_card(self, parent: tk.Widget, title: str, value: str, color: str) -> tk.Label:
        card = tk.Frame(parent, bg=PANEL, padx=15, pady=12, highlightthickness=1,
                        highlightbackground="#1a354a")
        card.pack(side="left", fill="x", expand=True, padx=5, pady=(0, 4))
        tk.Label(card, text=title, bg=PANEL, fg=MUTED, font=("Consolas", 9, "bold")).pack(anchor="w")
        value_label = tk.Label(card, text=value, bg=PANEL, fg=color,
                               font=("Consolas", 15, "bold"))
        value_label.pack(anchor="w", pady=(6, 0))
        return value_label

    def _tick_clock(self) -> None:
        self.clock.configure(text=datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
        self.root.after(1000, self._tick_clock)

    def _poll(self) -> None:
        if self.live_enabled:
            self.refresh_connections()
        self.root.after(5000, self._poll)

    def toggle_poll(self) -> None:
        self.live_enabled = not self.live_enabled
        self.live_status.configure(text="Auto-refresh paused." if not self.live_enabled else "Auto-refresh resumed.")
    
    def refresh_connections(self) -> None:
        try:
            rows = get_live_connections()
            self.live_rows = rows
            for item in self.connections.get_children():
                self.connections.delete(item)
            for row in rows[:250]:
                local = f"{row.get('LocalAddress', '')}:{row.get('LocalPort', '')}"
                remote = f"{row.get('RemoteAddress', '')}:{row.get('RemotePort', '')}"
                self.connections.insert("", "end", values=(local, remote, row.get("State", ""), row.get("OwningProcess", "")))
            self.connection_value.configure(text=str(len(rows)))
            self.live_status.configure(text=f"Updated {datetime.now().strftime('%H:%M:%S')} • showing up to 250 rows",
                                       fg=GREEN)
        except Exception as exc:
            self.connection_value.configure(text="N/A")
            self.live_status.configure(text=f"Live view unavailable: {str(exc)[:90]}", fg=AMBER)

    def _draw_network(self) -> None:
        canvas = self.graph
        canvas.delete("all")
        width = max(canvas.winfo_width(), 350)
        height = max(canvas.winfo_height(), 205)
        nodes = [
            (width * .16, height * .52, "DEVICE"),
            (width * .50, height * .25, "GATEWAY"),
            (width * .84, height * .52, "RELAY"),
        ]
        for a, b in ((nodes[0], nodes[1]), (nodes[1], nodes[2])):
            canvas.create_line(a[0], a[1], b[0], b[1], fill="#1e647c", width=2, dash=(5, 4))
        for x, y, name in nodes:
            canvas.create_oval(x-28, y-28, x+28, y+28, fill="#103448", outline=CYAN, width=2)
            canvas.create_text(x, y, text="●", fill=GREEN, font=("Consolas", 16))
            canvas.create_text(x, y+43, text=name, fill=TEXT, font=("Consolas", 8, "bold"))
        canvas.create_text(width/2, height-16, text="SIMULATED ENCRYPTED MESSAGE FLOW",
                           fill=MUTED, font=("Consolas", 8))

    def run_simulation(self) -> None:
        self.sim_events = make_simulated_events()
        self.timeline.delete(0, tk.END)
        for event in self.sim_events:
            line = (f"{event['time']}  {event['packet']}  {event['source']} -> "
                    f"{event['destination']}  {event['bytes']} B  [{event['state']}]")
            self.timeline.insert(tk.END, line)
        self.sim_value.configure(text=str(len(self.sim_events)))
        self._draw_network()

    def clear_simulation(self) -> None:
        self.sim_events.clear()
        self.timeline.delete(0, tk.END)
        self.sim_value.configure(text="0")
        self._draw_network()


def main() -> None:
    root = tk.Tk()
    JarvisDashboard(root)
    root.mainloop()


if __name__ == "__main__":
    main()
