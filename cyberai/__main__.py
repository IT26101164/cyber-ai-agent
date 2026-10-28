"""Run with: python -m cyberai"""
import json
from pathlib import Path
from cyberai.audit import AuditLog
from cyberai.defense import analyze_log
from cyberai.llm import ModelError, ask_cloud, ask_local
from cyberai.memory import MemoryStore
from cyberai.research import fetch_public_page

ROOT = Path(__file__).resolve().parent.parent
MEMORY = MemoryStore(ROOT / "data" / "memory.db")
AUDIT = AuditLog(ROOT / "logs" / "audit.jsonl")
LOG_DIR = ROOT / "logs"

def help_text() -> str:
    return """Commands:
  /remember TEXT      Save a note to local SQLite memory
  /memory KEYWORDS    Search saved notes
  /analyze-log FILE   Analyze a .log/.txt file inside logs/
  /research HTTPS_URL Fetch a page from an allowlisted documentation host
  /cloud TEXT         Send a prompt to the configured cloud model
  /help               Show commands
  /quit               Exit
Normal text uses the local Ollama model."""

def main() -> None:
    print("CyberAI 0.1 | defensive research starter")
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
