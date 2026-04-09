#!/usr/bin/env python3
import time
import json
import os
import threading
import asyncio
from datetime import datetime
from rich.live import Live
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.console import Console
from rich.text import Text
from rich.prompt import Prompt
from state_manager import StateManager
from graph_manager import GraphManager
from artifact_manager import ArtifactManager

class Dashboard:
    def __init__(self):
        self.state_manager = StateManager()
        self.graph_manager = GraphManager()
        self.artifact_manager = ArtifactManager()
        self.console = Console()
        self.layout = self.make_layout()
        self.running = True
        self.last_command = "None"

    def make_layout(self) -> Layout:
        layout = Layout()
        layout.split(
            Layout(name="header", size=3),
            Layout(name="main", ratio=1),
            Layout(name="footer", size=5), # Larger footer for interactive prompt
        )
        layout["main"].split_row(
            Layout(name="left", ratio=1),
            Layout(name="right", ratio=1),
        )
        layout["left"].split_column(
            Layout(name="heatmap", ratio=1),
            Layout(name="findings", ratio=1),
        )
        layout["right"].split_column(
            Layout(name="red_log", ratio=1),
            Layout(name="blue_log", ratio=1),
        )
        return layout

    def get_header(self, state) -> Panel:
        eng = state.get("engagement", {})
        grid = Table.grid(expand=True)
        grid.add_column(justify="left", ratio=1)
        grid.add_column(justify="center", ratio=1)
        grid.add_column(justify="right", ratio=1)
        
        title = Text("🛡️ OpenElia War Room", style="bold magenta")
        target = Text(f"Target: {eng.get('target', 'N/A')}", style="bold yellow")
        status = Text(f"Phase: {state.get('current_phase', 'N/A').upper()}", style="bold green")
        
        grid.add_row(title, target, status)
        return Panel(grid, style="white on blue")

    def get_heatmap(self, state) -> Panel:
        findings = state.get("findings", [])
        heatmap = self.graph_manager.get_mitre_heatmap(findings)
        table = Table(title="MITRE ATT&CK Coverage", expand=True, box=None)
        table.add_column("Tactic", style="cyan")
        table.add_column("Coverage", justify="right")
        if "error" in heatmap: return Panel(Text("MITRE data not found", style="red"))
        for tactic, data in heatmap.items():
            pct = data["coverage_pct"]
            color = "green" if pct > 50 else "yellow" if pct > 0 else "red"
            bar = "█" * int(pct / 10) + "░" * (10 - int(pct / 10))
            table.add_row(tactic, f"[{color}]{bar} {pct:.0f}%[/]")
        return Panel(table, border_style="cyan", title="[bold]Strategic Heatmap[/]")

    def get_findings(self, state) -> Panel:
        findings = state.get("findings", [])
        table = Table(expand=True, box=None)
        table.add_column("ID", style="dim", width=12)
        table.add_column("Severity", width=10)
        table.add_column("Finding")
        sev_colors = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "green", "info": "blue"}
        for f in findings[:10]:
            sev = f.get("severity", "info")
            table.add_row(f.get("id", "N/A"), Text(sev.upper(), style=sev_colors.get(sev, "white")), f.get("title", "N/A"))
        return Panel(table, border_style="yellow", title="[bold]Critical Findings[/]")

    def get_red_log(self, state) -> Panel:
        log_lines = []
        try:
            with open("state/audit.log", "r") as f:
                lines = f.readlines()
                for line in lines[-15:]:
                    data = json.loads(line)
                    if data.get("status") == "AUTHORIZED":
                        ts = data.get("timestamp", "").split("T")[1][:8]
                        log_lines.append(f"[dim]{ts}[/] [bold red]RED[/] -> {data.get('payload', '')[:50]}...")
        except Exception:
            log_lines = ["No red team logs found."]
        return Panel("\n".join(log_lines), border_style="red", title="[bold]Red Team Activity[/]")

    def get_blue_log(self, state) -> Panel:
        alerts = state.get("blue_alerts", [])
        log_lines = []
        for a in alerts[-10:]:
            ts = a.get("timestamp", "").split("T")[1][:8]
            sev = a.get("severity", "low")
            color = "red" if sev == "high" else "yellow" if sev == "medium" else "blue"
            log_lines.append(f"[dim]{ts}[/] [bold blue]BLUE[/] ! [{color}]{a.get('type')}[/] - {a.get('description')[:40]}...")
        return Panel("\n".join(log_lines), border_style="blue", title="[bold]Blue Team Telemetry[/]")

    def get_footer(self) -> Panel:
        artifacts = self.artifact_manager.list_artifacts()
        text = f"📦 Evidence Bag: {len(artifacts)} items | Last Cmd: [cyan]{self.last_command}[/]\n"
        text += "[bold yellow]COMMANDS:[/bold yellow] /pause, /resume, /target <ip>, /clear, /exit"
        return Panel(text, style="white on black", title="[bold]Interactive Command Center[/]")

    def update_loop(self, live):
        while self.running:
            state = self.state_manager.read()
            if state:
                self.layout["header"].update(self.get_header(state))
                self.layout["heatmap"].update(self.get_heatmap(state))
                self.layout["findings"].update(self.get_findings(state))
                self.layout["red_log"].update(self.get_red_log(state))
                self.layout["blue_log"].update(self.get_blue_log(state))
                self.layout["footer"].update(self.get_footer())
            time.sleep(1)

    def run(self):
        with Live(self.layout, refresh_per_second=4, screen=True) as live:
            # Start background update thread
            thread = threading.Thread(target=self.update_loop, args=(live,))
            thread.daemon = True
            thread.start()

            try:
                while self.running:
                    # Tier 4: Interactive Command Center
                    cmd = Prompt.ask("\n[bold magenta]OpenElia[/bold magenta]")
                    self.last_command = cmd
                    
                    if cmd == "/exit":
                        self.running = False
                    elif cmd.startswith("/target "):
                        new_target = cmd.split(" ")[1]
                        self.last_command = f"Target set to {new_target}"
                    elif cmd == "/clear":
                        self.last_command = "Dashboard state cleared"
                    elif cmd == "/pause":
                        # Tier 1: Activate Global Kill-Switch
                        self.state_manager.set_locked(True)
                        self.last_command = "🛑 EMERGENCY PAUSE: All agents locked."
                    elif cmd == "/resume":
                        # Tier 1: Deactivate Global Kill-Switch
                        self.state_manager.set_locked(False)
                        self.last_command = "▶️ RESUMED: Agents unlocked."
                    else:
                        self.last_command = f"Unknown command: {cmd}"
            except KeyboardInterrupt:
                self.running = False

if __name__ == "__main__":
    Dashboard().run()
