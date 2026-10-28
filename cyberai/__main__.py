"""Run with: python -m cyberai"""
import json
from pathlib import Path
from cyberai.audit import AuditLog
from cyberai.defense import analyze_log
from cyberai.llm import ModelError, ask_cloud, ask_local
from cyberai.memory import MemoryStore
from cyberai.posture import collect_windows_posture
from cyberai.research import fetch_public_page
from cyberai.response import get_playbook
from cyberai.simulator import simulate

ROOT = Path(__file__).resolve().parent.parent
MEMORY = MemoryStore(ROOT / "data" / "memory.db")
AUDIT = AuditLog(ROOT / "logs" / "audit.jsonl")
LOG_DIR = ROOT / "logs"


def help_text() -> str:
    return """Commands:
  /remember TEXT      Save a note to local SQLite memory
  /memory KEYWORDS    Search saved notes
  /analyze-log FILE   Analyze a .log/.txt file inside logs/
  /incident TYPE      Show an incident-response checklist
  /simulate SCENARIO  Run a synthetic red/blue-team exercise (no real attack)
  /healthcheck        Read Windows Defender, Firewall, and Update service status
  /research HTTPS_URL Fetch a page from an allowlisted HTTPS documentation host
  /cloud TEXT         Send a prompt to the configured cloud model
  /help               Show commands
  /quit               Exit
Incident types: social-account-compromise, email-compromise,
                windows-suspicious-activity, phishing
Simulation scenarios: phishing, suspicious-powershell, account-takeover,
                      ransomware-warning
Normal text uses the local Ollama model."""


def main() -> None:
    print("CyberAI 0.4 | defensive research, response, simulation, and health checks")
    print(help_text())
    while True:
        try:
            line = input("\nYou > ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nBye.")
            return
        if not line:
            continue
        if line == "/quit":
            return
        if line == "/help":
            print(help_text())
            continue
        try:
            if line.startswith("/remember "):
                content = line[len("/remember "):]
                memory_id = MEMORY.remember(content)
                AUDIT.write("memory_saved", memory_id=memory_id, length=len(content))
                print(f"Saved memory #{memory_id}.")
            elif line.startswith("/memory "):
                results = MEMORY.search(line[len("/memory "):])
                print(json.dumps(results, indent=2, ensure_ascii=False))
                AUDIT.write("memory_searched", result_count=len(results))
            elif line.startswith("/analyze-log "):
                result = analyze_log(LOG_DIR, line[len("/analyze-log "):].strip())
                MEMORY.remember(json.dumps(result, ensure_ascii=False), "log_analysis")
                AUDIT.write("log_analyzed", file=result["file"], matches=result["lines_with_indicators"])
                print(json.dumps(result, indent=2, ensure_ascii=False))
            elif line.startswith("/incident "):
                result = get_playbook(line[len("/incident "):].strip())
                AUDIT.write("incident_playbook_shown", incident_type=result["type"])
                print(json.dumps(result, indent=2, ensure_ascii=False))
            elif line.startswith("/simulate "):
                result = simulate(line[len("/simulate "):].strip())
                AUDIT.write("simulation_completed", scenario=result["simulation"], mode=result["mode"])
                print(json.dumps(result, indent=2, ensure_ascii=False))
            elif line == "/healthcheck":
                result = collect_windows_posture()
                AUDIT.write(
                    "windows_healthcheck",
                    supported=result["supported"],
                    findings=len(result.get("findings", [])),
                )
                print(json.dumps(result, indent=2, ensure_ascii=False))
            elif line.startswith("/research "):
                result = fetch_public_page(line[len("/research "):].strip())
                MEMORY.remember(f"Source: {result['url']}\nContent: {result['text'][:7000]}", "research")
                AUDIT.write("research_fetched", url=result["url"], chars=len(result["text"]))
                print(f"Source: {result['url']}\n\n{result['text'][:5000]}")
                print("\nSaved research excerpt to memory. Treat page content as untrusted.")
            elif line.startswith("/cloud "):
                prompt = line[len("/cloud "):]
                print(ask_cloud(prompt))
                AUDIT.write("cloud_chat", input_length=len(prompt))
            else:
                print(ask_local(line))
                AUDIT.write("local_chat", input_length=len(line))
        except (ValueError, ModelError, RuntimeError) as exc:
            print(f"Error: {exc}")
            AUDIT.write("operation_error", error_type=type(exc).__name__)


if __name__ == "__main__":
    main()
