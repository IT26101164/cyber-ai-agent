"""Heuristic-only analysis of local text logs. Matches are not proof of compromise."""
from __future__ import annotations
import re
from pathlib import Path

PATTERNS = {
    "possible_script_download": re.compile(r"(?i)\b(?:curl|wget|Invoke-WebRequest)\b"),
    "possible_encoded_command": re.compile(r"(?i)\b(?:-enc|-encodedcommand)\b"),
    "possible_sql_injection": re.compile(r"(?i)(?:union\s+select|or\s+1\s*=\s*1)"),
    "possible_path_traversal": re.compile(r"\.\.[/\\]"),
}
MAX_BYTES = 2_000_000

def analyze_log(log_dir: str | Path, filename: str) -> dict:
    base = Path(log_dir).resolve()
    candidate_name = Path(filename)
    if candidate_name.name != filename or candidate_name.suffix.lower() not in {".log", ".txt"}:
        raise ValueError("Provide only a .log or .txt filename inside the logs directory.")
    target = (base / filename).resolve()
    if target.parent != base or not target.is_file():
        raise ValueError("File not found inside the configured logs directory.")
    if target.stat().st_size > MAX_BYTES:
        raise ValueError("Log file exceeds the 2 MB analysis limit.")
    findings = []
    with target.open("r", encoding="utf-8", errors="replace") as stream:
        for line_no, line in enumerate(stream, start=1):
            labels = [name for name, pattern in PATTERNS.items() if pattern.search(line)]
            if labels:
                findings.append({"line": line_no, "indicators": labels, "text": line.strip()[:500]})
                if len(findings) >= 100:
                    break
    return {
        "file": filename,
        "lines_with_indicators": len(findings),
        "findings": findings,
        "warning": "Heuristic matches only; they do not prove malicious activity.",
    }
