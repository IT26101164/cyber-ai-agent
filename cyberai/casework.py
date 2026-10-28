"""Local evidence and case-work manager for authorized cyber investigations.

All records stay in a local SQLite database and evidence vault. This module
never contacts a service provider, tracks a person, scans a network, or takes
response actions. It organizes evidence that the operator lawfully provides.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import mimetypes
import os
import re
import sqlite3
import uuid
import webbrowser
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlsplit

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, simpledialog, ttk
except ImportError:  # Importable in headless CI for pure storage tests.
    tk = None  # type: ignore[assignment]
    ttk = None  # type: ignore[assignment]
    filedialog = messagebox = simpledialog = None  # type: ignore[assignment]


# Reuse the visual language of the JARVIS SOC screen without importing its UI module.
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


CASE_STATUSES = ("OPEN", "INVESTIGATING", "AWAITING_LEGAL_PROCESS", "CLOSED")
TEXT_EXTENSIONS = {".txt", ".log", ".csv", ".json", ".eml", ".html", ".htm", ".xml", ".md"}
MAX_EVIDENCE_BYTES = 100 * 1024 * 1024
MAX_TEXT_SCAN_BYTES = 5 * 1024 * 1024
ZERO_HASH = "0" * 64

IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
URL_RE = re.compile(r"(?i)\bhttps?://[^\s<>\"']+")
EMAIL_RE = re.compile(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,63}\b")
DOMAIN_RE = re.compile(r"(?i)(?<![@\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![\w.-])")
SHA256_RE = re.compile(r"(?i)\b[a-f0-9]{64}\b")
PHONE_RE = re.compile(r"(?<![\w+])\+(?:\d[\s().-]?){7,18}\d(?!\w)")

PHONE_LEAD_STATUSES = (
    "UNVERIFIED", "COMPLAINANT", "WITNESS", "CONTACT", "SUBJECT_OF_INQUIRY",
)
PHONE_LEGAL_BASES = (
    "LEAD_ONLY_NOT_LOCATION_AUTHORITY", "CONSENT", "WARRANT_OR_COURT_ORDER",
    "AUTHORIZED_PROVIDER_RESPONSE", "OTHER_REVIEWED",
)
LOCATION_SOURCES = (
    "PROVIDER_RESPONSE", "CONSENTED_DEVICE_EXPORT",
    "OFFICER_ENTERED_FROM_RECORD", "OTHER_AUTHORIZED_SOURCE",
)
LOCATION_LEGAL_BASES = (
    "CONSENT", "WARRANT_OR_COURT_ORDER",
    "AUTHORIZED_PROVIDER_RESPONSE", "OTHER_REVIEWED",
)


# Require a full calendar date; ambiguous syslog fragments without a year are ignored.
ISO_TIMESTAMP_RE = re.compile(
    r"(?<!\d)(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"
    r"(?:\.\d{1,6})?(?:Z|[+-]\d{2}:?\d{2})?)(?!\d)"
)
APACHE_TIMESTAMP_RE = re.compile(
    r"\[(?P<timestamp>\d{1,2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]"
)
RFC2822_TIMESTAMP_RE = re.compile(
    r"(?P<timestamp>\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),?\s+\d{1,2}\s+"
    r"[A-Za-z]{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+[+-]\d{4}\b)"
)


def utc_now() -> str:
    """UTC timestamp in an unambiguous ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _canonical_json(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _safe_filename(name: str) -> str:
    base = Path(name).name
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", base).strip("._")
    return (cleaned or "evidence.bin")[:120]


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def extract_indicators(text: str) -> list[tuple[str, str]]:
    """Extract modest, explainable indicators from operator-supplied text only."""
    found: set[tuple[str, str]] = set()
    for match in URL_RE.findall(text):
        value = match.rstrip(".,;:!?)\"]}")
        if len(value) <= 2048:
            parsed = urlsplit(value)
            if parsed.scheme in ("http", "https") and parsed.hostname:
                found.add(("url", value))
                host = parsed.hostname.rstrip(".").lower()
                if host:
                    found.add(("domain", host))
    for match in EMAIL_RE.findall(text):
        found.add(("email", match.lower()))
    for match in IPV4_RE.findall(text):
        try:
            found.add(("ipv4", str(ipaddress.IPv4Address(match))))
        except ipaddress.AddressValueError:
            pass
    for match in SHA256_RE.findall(text):
        found.add(("sha256", match.lower()))
    for match in PHONE_RE.findall(text):
        digits = re.sub(r"\D", "", match)
        if 8 <= len(digits) <= 15 and digits[0] != "0":
            found.add(("phone", "+" + digits))
    for match in DOMAIN_RE.findall(text):
        domain = match.rstrip(".").lower()
        if domain and "@" not in domain:
            found.add(("domain", domain))
    return sorted(found, key=lambda item: (item[0], item[1]))


def extract_timestamps(text: str) -> list[dict[str, Any]]:
    """Extract dated events without guessing missing years or time zones.

    Supports ISO-8601, Apache access-log dates, and RFC-2822 mail dates.
    Naive timestamps are retained as recorded and are never labeled UTC.
    """
    patterns = (
        (ISO_TIMESTAMP_RE, "ISO-8601"),
        (APACHE_TIMESTAMP_RE, "APACHE"),
        (RFC2822_TIMESTAMP_RE, "RFC-2822"),
    )
    events: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        if len(raw_line) > 8192:
            continue
        matches: list[tuple[int, int, str, str]] = []
        for pattern, parser_name in patterns:
            for match in pattern.finditer(raw_line):
                matches.append((match.start("timestamp"), match.end("timestamp"), match.group("timestamp"), parser_name))
        matches.sort(key=lambda item: (item[0], -(item[1] - item[0])))
        accepted: list[tuple[int, int, str, str]] = []
        for candidate in matches:
            if any(candidate[0] < end and candidate[1] > start for start, end, _, _ in accepted):
                continue
            accepted.append(candidate)
        for _start, _end, raw_timestamp, parser_name in accepted:
            try:
                if parser_name == "APACHE":
                    parsed = datetime.strptime(raw_timestamp, "%d/%b/%Y:%H:%M:%S %z")
                elif parser_name == "RFC-2822":
                    fmt = "%a, %d %b %Y %H:%M:%S %z" if "," in raw_timestamp else "%a %d %b %Y %H:%M:%S %z"
                    parsed = datetime.strptime(raw_timestamp, fmt)
                else:
                    parsed = datetime.fromisoformat(raw_timestamp.replace("Z", "+00:00"))
            except ValueError:
                continue
            aware = parsed.tzinfo is not None and parsed.utcoffset() is not None
            events.append({
                "timestamp_raw": raw_timestamp,
                "timestamp_utc": parsed.astimezone(timezone.utc).isoformat(timespec="seconds") if aware else None,
                "timestamp_wall": parsed.replace(tzinfo=None).isoformat(timespec="seconds"),
                "timezone_status": "EXPLICIT_OFFSET" if aware else "UNSPECIFIED",
                "parser": parser_name,
                "line_number": line_number,
                "context": raw_line.strip()[:600],
            })
    return events


def normalize_phone_number(value: str) -> str:
    """Normalize an explicitly international telephone number to E.164.

    The tool does not infer a country code from caller location or a number prefix.
    """
    raw = str(value or "").strip()
    if raw.startswith("00"):
        raw = "+" + raw[2:]
    cleaned = re.sub(r"[\s().-]", "", raw)
    if not re.fullmatch(r"\+[1-9]\d{7,14}", cleaned):
        raise ValueError("Enter an international number in E.164 format, e.g. +94712345678.")
    return cleaned


def validate_authority_reference(legal_basis: str, reference: str, *, location: bool = False) -> str:
    """Require a traceable reference for authorization-dependent work."""
    allowed = LOCATION_LEGAL_BASES if location else PHONE_LEGAL_BASES
    if legal_basis not in allowed:
        raise ValueError("Select a supported legal/consent basis.")
    clean_ref = str(reference or "").strip()
    if legal_basis != "LEAD_ONLY_NOT_LOCATION_AUTHORITY" and len(clean_ref) < 3:
        raise ValueError("Enter the relevant consent, warrant/order, provider-request or reviewed-authority reference.")
    if location and len(clean_ref) < 3:
        raise ValueError("Location records require an authorization/consent reference.")
    if len(clean_ref) > 300:
        raise ValueError("Authority reference must be 300 characters or fewer.")
    return clean_ref


def parse_explicit_datetime(value: str) -> datetime:
    """Parse an ISO-8601 datetime only when its timezone offset is explicit."""
    raw = str(value or "").strip()
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Use ISO-8601 date/time with an explicit timezone, e.g. 2026-10-28T15:30:00+05:30.") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("Timestamp must include a timezone offset; timezone-naive times are not accepted.")
    return parsed.astimezone(timezone.utc)


def openstreetmap_url(latitude: float, longitude: float) -> str:
    """Return a map URL for manually supplied coordinates, never a phone-number lookup."""
    lat, lon = float(latitude), float(longitude)
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        raise ValueError("Coordinates are outside valid latitude/longitude ranges.")
    return f"https://www.openstreetmap.org/?mlat={lat:.6f}&mlon={lon:.6f}#map=16/{lat:.6f}/{lon:.6f}"


class CaseStore:
    """SQLite-backed case register, evidence vault metadata and tamper-evident audit."""

    def __init__(self, data_dir: str | Path | None = None):
        root = Path(data_dir) if data_dir is not None else Path(__file__).resolve().parents[1] / "data" / "casework"
        self.data_dir = root.resolve()
        self.db_path = self.data_dir / "casework.sqlite3"
        self.vault_dir = self.data_dir / "evidence_vault"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.actor = os.environ.get("CYBERAI_OPERATOR", "local-operator")[:80]
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.db_path, timeout=10)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA foreign_keys = ON")
        con.execute("PRAGMA busy_timeout = 10000")
        return con

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        con = self._connect()
        try:
            con.execute("BEGIN IMMEDIATE")
            yield con
            con.commit()
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()

    def _initialize(self) -> None:
        with self._write() as con:
            con.executescript("""
                CREATE TABLE IF NOT EXISTS cases (
                    case_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL CHECK(status IN ('OPEN','INVESTIGATING','AWAITING_LEGAL_PROCESS','CLOSED')),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    created_by TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS evidence (
                    evidence_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    original_name TEXT NOT NULL,
                    stored_path TEXT NOT NULL UNIQUE,
                    sha256 TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    media_type TEXT NOT NULL,
                    source_label TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    collected_at TEXT NOT NULL,
                    added_by TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS indicators (
                    indicator_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
                    indicator_type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    UNIQUE(evidence_id, indicator_type, value)
                );
                CREATE TABLE IF NOT EXISTS phone_leads (
                    phone_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    phone_number TEXT NOT NULL,
                    lead_status TEXT NOT NULL CHECK(lead_status IN ('UNVERIFIED','COMPLAINANT','WITNESS','CONTACT','SUBJECT_OF_INQUIRY')),
                    source_label TEXT NOT NULL,
                    legal_basis TEXT NOT NULL CHECK(legal_basis IN ('LEAD_ONLY_NOT_LOCATION_AUTHORITY','CONSENT','WARRANT_OR_COURT_ORDER','AUTHORIZED_PROVIDER_RESPONSE','OTHER_REVIEWED')),
                    authority_reference TEXT NOT NULL DEFAULT '',
                    notes TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    UNIQUE(case_id, phone_number)
                );
                CREATE TABLE IF NOT EXISTS location_records (
                    location_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    phone_id TEXT NOT NULL REFERENCES phone_leads(phone_id),
                    observed_at_utc TEXT NOT NULL,
                    latitude REAL NOT NULL CHECK(latitude >= -90 AND latitude <= 90),
                    longitude REAL NOT NULL CHECK(longitude >= -180 AND longitude <= 180),
                    accuracy_m REAL,
                    source_label TEXT NOT NULL CHECK(source_label IN ('PROVIDER_RESPONSE','CONSENTED_DEVICE_EXPORT','OFFICER_ENTERED_FROM_RECORD','OTHER_AUTHORIZED_SOURCE')),
                    legal_basis TEXT NOT NULL CHECK(legal_basis IN ('CONSENT','WARRANT_OR_COURT_ORDER','AUTHORIZED_PROVIDER_RESPONSE','OTHER_REVIEWED')),
                    authority_reference TEXT NOT NULL,
                    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
                    evidence_sha256 TEXT NOT NULL,
                    notes TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    created_by TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS notes (
                    note_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    created_at TEXT NOT NULL,
                    author TEXT NOT NULL,
                    note TEXT NOT NULL,
                    note_sha256 TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    case_id TEXT,
                    details_json TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_phone_leads_case ON phone_leads(case_id, created_at);
                CREATE INDEX IF NOT EXISTS idx_location_case_time ON location_records(case_id, observed_at_utc);
                CREATE INDEX IF NOT EXISTS idx_location_phone_time ON location_records(phone_id, observed_at_utc);
                CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_id, collected_at);
                CREATE INDEX IF NOT EXISTS idx_indicators_case_value ON indicators(case_id, indicator_type, value);
                CREATE INDEX IF NOT EXISTS idx_audit_case ON audit_events(case_id, seq);
            """)
            note_columns = {row["name"] for row in con.execute("PRAGMA table_info(notes)").fetchall()}
            if "note_sha256" not in note_columns:
                con.execute("ALTER TABLE notes ADD COLUMN note_sha256 TEXT NOT NULL DEFAULT ''")

    def _event(
        self, con: sqlite3.Connection, event: str, case_id: str | None,
        details: dict[str, Any], actor: str | None = None,
    ) -> None:
        previous = con.execute("SELECT event_hash FROM audit_events ORDER BY seq DESC LIMIT 1").fetchone()
        prev_hash = previous["event_hash"] if previous else ZERO_HASH
        timestamp = utc_now()
        details_json = _canonical_json(details)
        cursor = con.execute(
            "INSERT INTO audit_events(timestamp,event,actor,case_id,details_json,prev_hash,event_hash) "
            "VALUES(?,?,?,?,?,?,?)",
            (timestamp, event, (actor or self.actor)[:80], case_id, details_json, prev_hash, ""),
        )
        seq = int(cursor.lastrowid)
        payload = {
            "seq": seq, "timestamp": timestamp, "event": event,
            "actor": (actor or self.actor)[:80], "case_id": case_id, "details": details,
        }
        event_hash = hashlib.sha256((prev_hash + _canonical_json(payload)).encode("utf-8")).hexdigest()
        con.execute("UPDATE audit_events SET event_hash=? WHERE seq=?", (event_hash, seq))

    def create_case(self, title: str, description: str = "", actor: str | None = None) -> dict[str, Any]:
        title = title.strip()
        if not title or len(title) > 180:
            raise ValueError("Case title must contain 1–180 characters.")
        if len(description) > 4000:
            raise ValueError("Case description must be 4,000 characters or fewer.")
        now = utc_now()
        case_id = "CASE-" + datetime.now(timezone.utc).strftime("%Y%m%d") + "-" + uuid.uuid4().hex[:8].upper()
        who = (actor or self.actor)[:80]
        with self._write() as con:
            con.execute(
                "INSERT INTO cases(case_id,title,description,status,created_at,updated_at,created_by) VALUES(?,?,?,?,?,?,?)",
                (case_id, title, description.strip(), "OPEN", now, now, who),
            )
            self._event(con, "CASE_CREATED", case_id, {"title": title, "status": "OPEN"}, who)
        return self.get_case(case_id)

    def get_case(self, case_id: str) -> dict[str, Any]:
        with closing(self._connect()) as con:
            row = con.execute("SELECT * FROM cases WHERE case_id=?", (case_id,)).fetchone()
        if not row:
            raise KeyError(f"Unknown case: {case_id}")
        return dict(row)

    def list_cases(self) -> list[dict[str, Any]]:
        with closing(self._connect()) as con:
            rows = con.execute("SELECT * FROM cases ORDER BY updated_at DESC, case_id").fetchall()
        return [dict(row) for row in rows]

    def set_case_status(self, case_id: str, status: str, actor: str | None = None) -> dict[str, Any]:
        status = status.strip().upper()
        if status not in CASE_STATUSES:
            raise ValueError(f"Status must be one of: {', '.join(CASE_STATUSES)}")
        now = utc_now()
        with self._write() as con:
            previous = con.execute("SELECT status FROM cases WHERE case_id=?", (case_id,)).fetchone()
            if not previous:
                raise KeyError(f"Unknown case: {case_id}")
            old_status = previous["status"]
            con.execute("UPDATE cases SET status=?, updated_at=? WHERE case_id=?", (status, now, case_id))
            self._event(con, "CASE_STATUS_CHANGED", case_id, {"from": old_status, "to": status}, actor)
        return self.get_case(case_id)

    def add_note(self, case_id: str, note: str, actor: str | None = None) -> dict[str, Any]:
        note = note.strip()
        if not note or len(note) > 10000:
            raise ValueError("A note must contain 1–10,000 characters.")
        who = (actor or self.actor)[:80]
        now, note_id = utc_now(), "NOTE-" + uuid.uuid4().hex[:12].upper()
        with self._write() as con:
            if not con.execute("SELECT 1 FROM cases WHERE case_id=?", (case_id,)).fetchone():
                raise KeyError(f"Unknown case: {case_id}")
            note_hash = hashlib.sha256(note.encode("utf-8")).hexdigest()
            con.execute("INSERT INTO notes(note_id,case_id,created_at,author,note,note_sha256) VALUES(?,?,?,?,?,?)",
                        (note_id, case_id, now, who, note, note_hash))
            con.execute("UPDATE cases SET updated_at=? WHERE case_id=?", (now, case_id))
            self._event(con, "NOTE_ADDED", case_id, {
                "note_id": note_id, "characters": len(note), "note_sha256": note_hash,
            }, who)
        return {"note_id": note_id, "case_id": case_id, "created_at": now, "author": who, "note": note}

    def list_notes(self, case_id: str) -> list[dict[str, Any]]:
        """Read stored investigator notes in reverse chronological order."""
        with closing(self._connect()) as con:
            rows = con.execute(
                "SELECT note_id,case_id,created_at,author,note,note_sha256 FROM notes "
                "WHERE case_id=? ORDER BY created_at DESC, note_id",
                (case_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def add_evidence(
        self, case_id: str, source_path: str | Path, source_label: str,
        description: str = "", actor: str | None = None,
    ) -> dict[str, Any]:
        source = Path(source_path).expanduser()
        if source.is_symlink() or not source.is_file():
            raise ValueError("Choose a regular local evidence file (symbolic links are not accepted).")
        if len(source_label.strip()) < 2 or len(source_label) > 300:
            raise ValueError("Source/provenance label must contain 2–300 characters.")
        if len(description) > 2000:
            raise ValueError("Evidence description must be 2,000 characters or fewer.")
        before = source.stat()
        if before.st_size > MAX_EVIDENCE_BYTES:
            raise ValueError("Evidence file exceeds the 100 MiB limit.")
        if before.st_size < 0:
            raise ValueError("Invalid file size.")
        case = self.get_case(case_id)
        evidence_id = "EV-" + uuid.uuid4().hex[:12].upper()
        safe_name = _safe_filename(source.name)
        case_vault = self.vault_dir / case_id
        case_vault.mkdir(parents=True, exist_ok=True)
        relative_path = str(Path(case_id) / f"{evidence_id}_{safe_name}")
        destination = self.vault_dir / relative_path
        digest = hashlib.sha256()
        written = 0
        try:
            with source.open("rb") as src, destination.open("xb") as dst:
                for chunk in iter(lambda: src.read(1024 * 1024), b""):
                    written += len(chunk)
                    if written > MAX_EVIDENCE_BYTES:
                        raise ValueError("Evidence file exceeded the size limit while copying.")
                    digest.update(chunk)
                    dst.write(chunk)
            after = source.stat()
            if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns or written != before.st_size:
                raise RuntimeError("Source file changed while it was being copied; try again with a stable file.")
            hexdigest = digest.hexdigest()
            media_type = mimetypes.guess_type(safe_name)[0] or "application/octet-stream"
            collected_at, who = utc_now(), (actor or self.actor)[:80]
            indicator_pairs: list[tuple[str, str]] = []
            if source.suffix.lower() in TEXT_EXTENSIONS and written <= MAX_TEXT_SCAN_BYTES:
                try:
                    indicator_pairs = extract_indicators(destination.read_text(encoding="utf-8", errors="replace"))
                except OSError:
                    indicator_pairs = []
            with self._write() as con:
                if not con.execute("SELECT 1 FROM cases WHERE case_id=?", (case_id,)).fetchone():
                    raise KeyError(f"Unknown case: {case_id}")
                con.execute(
                    "INSERT INTO evidence(evidence_id,case_id,original_name,stored_path,sha256,size_bytes,media_type,source_label,description,collected_at,added_by) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (evidence_id, case_id, source.name[:255], relative_path, hexdigest, written,
                     media_type, source_label.strip(), description.strip(), collected_at, who),
                )
                con.executemany(
                    "INSERT OR IGNORE INTO indicators(case_id,evidence_id,indicator_type,value) VALUES(?,?,?,?)",
                    [(case_id, evidence_id, kind, value) for kind, value in indicator_pairs],
                )
                con.execute("UPDATE cases SET updated_at=? WHERE case_id=?", (collected_at, case_id))
                self._event(con, "EVIDENCE_IMPORTED", case_id, {
                    "evidence_id": evidence_id, "filename": source.name[:255],
                    "sha256": hexdigest, "size_bytes": written, "media_type": media_type,
                    "source_label": source_label.strip(), "indicator_count": len(indicator_pairs),
                }, who)
        except Exception:
            try:
                destination.unlink(missing_ok=True)
            except OSError:
                pass
            raise
        return self.get_evidence(evidence_id)

    def get_evidence(self, evidence_id: str) -> dict[str, Any]:
        with closing(self._connect()) as con:
            row = con.execute("SELECT * FROM evidence WHERE evidence_id=?", (evidence_id,)).fetchone()
        if not row:
            raise KeyError(f"Unknown evidence: {evidence_id}")
        item = dict(row)
        item["absolute_path"] = str(self.vault_dir / item["stored_path"])
        return item

    def list_evidence(self, case_id: str) -> list[dict[str, Any]]:
        with closing(self._connect()) as con:
            rows = con.execute(
                "SELECT * FROM evidence WHERE case_id=? ORDER BY collected_at DESC, evidence_id",
                (case_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def verify_evidence(self, evidence_id: str) -> dict[str, Any]:
        item = self.get_evidence(evidence_id)
        path = self.vault_dir / item["stored_path"]
        if not path.is_file():
            actual, status = None, "MISSING"
        else:
            actual = sha256_file(path)
            status = "MATCH" if actual == item["sha256"] else "HASH_MISMATCH"
        with self._write() as con:
            self._event(con, "EVIDENCE_INTEGRITY_CHECK", item["case_id"], {
                "evidence_id": evidence_id, "status": status, "expected_sha256": item["sha256"],
                "actual_sha256": actual,
            })
        return {"evidence_id": evidence_id, "status": status, "expected_sha256": item["sha256"], "actual_sha256": actual}

    def verify_case_evidence(self, case_id: str) -> list[dict[str, Any]]:
        return [self.verify_evidence(item["evidence_id"]) for item in self.list_evidence(case_id)]

    def list_indicators(self, case_id: str) -> list[dict[str, Any]]:
        with closing(self._connect()) as con:
            rows = con.execute(
                "SELECT i.indicator_type, i.value, i.evidence_id, e.original_name "
                "FROM indicators i JOIN evidence e ON e.evidence_id=i.evidence_id "
                "WHERE i.case_id=? ORDER BY i.indicator_type, i.value, e.original_name",
                (case_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def correlations(self, case_id: str) -> list[dict[str, Any]]:
        """Return repeated indicators across separate evidence files; this is a lead, not attribution."""
        grouped: dict[tuple[str, str], dict[str, Any]] = {}
        for row in self.list_indicators(case_id):
            key = (row["indicator_type"], row["value"])
            item = grouped.setdefault(key, {"indicator_type": key[0], "value": key[1], "evidence_ids": set(), "filenames": set()})
            item["evidence_ids"].add(row["evidence_id"])
            item["filenames"].add(row["original_name"])
        result = []
        for item in grouped.values():
            if len(item["evidence_ids"]) >= 2:
                result.append({
                    "indicator_type": item["indicator_type"], "value": item["value"],
                    "evidence_count": len(item["evidence_ids"]),
                    "evidence_ids": sorted(item["evidence_ids"]), "filenames": sorted(item["filenames"]),
                    "interpretation": "Repeated indicator across evidence files; confirm time, context and alternative explanations.",
                })
        return sorted(result, key=lambda x: (-x["evidence_count"], x["indicator_type"], x["value"]))

    def timeline(self, case_id: str, limit: int = 500) -> list[dict[str, Any]]:
        with closing(self._connect()) as con:
            if not con.execute("SELECT 1 FROM cases WHERE case_id=?", (case_id,)).fetchone():
                raise KeyError(f"Unknown case: {case_id}")
            rows = con.execute(
                "SELECT seq,timestamp,event,actor,case_id,details_json,prev_hash,event_hash "
                "FROM audit_events WHERE case_id=? ORDER BY seq DESC LIMIT ?",
                (case_id, max(1, min(int(limit), 5000))),
            ).fetchall()
        result = []
        for row in reversed(rows):
            item = dict(row)
            item["details"] = json.loads(item.pop("details_json"))
            result.append(item)
        return result

    def evidence_timeline(self, case_id: str, limit: int = 2000) -> dict[str, Any]:
        """Build a best-effort timeline from hash-verified, locally imported text evidence."""
        self.get_case(case_id)
        events: list[dict[str, Any]] = []
        warnings: list[dict[str, str]] = []
        scanned = 0
        for evidence in self.list_evidence(case_id):
            filename = evidence["original_name"]
            evidence_id = evidence["evidence_id"]
            if Path(filename).suffix.lower() not in TEXT_EXTENSIONS:
                warnings.append({"evidence_id": evidence_id, "filename": filename, "reason": "Unsupported file type for timestamp parsing"})
                continue
            if int(evidence["size_bytes"]) > MAX_TEXT_SCAN_BYTES:
                warnings.append({"evidence_id": evidence_id, "filename": filename, "reason": "Text exceeds the 5 MiB timestamp-parsing limit"})
                continue
            path = self.vault_dir / evidence["stored_path"]
            if not path.is_file():
                warnings.append({"evidence_id": evidence_id, "filename": filename, "reason": "Stored evidence file is missing"})
                continue
            try:
                if sha256_file(path) != evidence["sha256"]:
                    warnings.append({"evidence_id": evidence_id, "filename": filename, "reason": "SHA-256 mismatch; content was not parsed"})
                    continue
                text_value = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                warnings.append({"evidence_id": evidence_id, "filename": filename, "reason": f"Read error: {str(exc)[:160]}"})
                continue
            scanned += 1
            for event in extract_timestamps(text_value):
                try:
                    parsed = datetime.fromisoformat(event["timestamp_utc"]) if event["timestamp_utc"] else datetime.fromisoformat(event["timestamp_wall"]).replace(tzinfo=timezone.utc)
                    sort_epoch = parsed.timestamp()
                except (TypeError, ValueError, OverflowError):
                    sort_epoch = 0.0
                indicators = [
                    {"indicator_type": kind, "value": value}
                    for kind, value in extract_indicators(event["context"])
                ]
                events.append({
                    **event,
                    "evidence_id": evidence_id,
                    "filename": filename,
                    "evidence_sha256": evidence["sha256"],
                    "indicators": indicators,
                    "_sort_epoch": sort_epoch,
                })
        events.sort(key=lambda item: (item["_sort_epoch"], item["evidence_id"], item["line_number"]))
        events = events[:max(1, min(int(limit), 5000))]
        grouped: dict[tuple[str, str], dict[str, Any]] = {}
        for event in events:
            for indicator in event["indicators"]:
                key = (indicator["indicator_type"], indicator["value"])
                lead = grouped.setdefault(key, {
                    "indicator_type": key[0], "value": key[1],
                    "evidence_ids": set(), "filenames": set(), "event_refs": [],
                })
                lead["evidence_ids"].add(event["evidence_id"])
                lead["filenames"].add(event["filename"])
                lead["event_refs"].append({
                    "evidence_id": event["evidence_id"],
                    "filename": event["filename"],
                    "line_number": event["line_number"],
                    "timestamp_raw": event["timestamp_raw"],
                    "timestamp_utc": event["timestamp_utc"],
                    "timezone_status": event["timezone_status"],
                })
        correlations = []
        for lead in grouped.values():
            if len(lead["evidence_ids"]) >= 2:
                correlations.append({
                    "indicator_type": lead["indicator_type"],
                    "value": lead["value"],
                    "evidence_count": len(lead["evidence_ids"]),
                    "evidence_ids": sorted(lead["evidence_ids"]),
                    "filenames": sorted(lead["filenames"]),
                    "event_refs": lead["event_refs"][:50],
                    "interpretation": "Indicator appears in timestamped lines from separate evidence files; review clock settings, context and alternative explanations. This does not identify a person.",
                })
        correlations.sort(key=lambda item: (-item["evidence_count"], item["indicator_type"], item["value"]))
        return {
            "events": events,
            "timeline_correlation_leads": correlations,
            "warnings": warnings,
            "evidence_files_scanned": scanned,
            "event_count": len(events),
            "ordering_note": "Entries with no explicit timezone are placed by their recorded wall-clock value as a convenience; their order relative to timezone-aware events may be wrong.",
        }

    def case_summary(self, case_id: str) -> dict[str, Any]:
        case = self.get_case(case_id)
        with closing(self._connect()) as con:
            evidence_count = con.execute("SELECT COUNT(*) FROM evidence WHERE case_id=?", (case_id,)).fetchone()[0]
            indicator_count = con.execute("SELECT COUNT(*) FROM indicators WHERE case_id=?", (case_id,)).fetchone()[0]
            note_count = con.execute("SELECT COUNT(*) FROM notes WHERE case_id=?", (case_id,)).fetchone()[0]
        return {
            **case, "evidence_count": evidence_count, "indicator_count": indicator_count,
            "correlation_count": len(self.correlations(case_id)), "note_count": note_count,
        }

    def audit_integrity(self) -> dict[str, Any]:
        """Verify the local hash chain. It is tamper-evident, not a signed external guarantee."""
        with closing(self._connect()) as con:
            rows = con.execute("SELECT * FROM audit_events ORDER BY seq").fetchall()
            notes = {
                row["note_id"]: dict(row)
                for row in con.execute("SELECT note_id,note_sha256,note FROM notes").fetchall()
            }
        previous = ZERO_HASH
        checked = 0
        for row in rows:
            item = dict(row)
            try:
                details = json.loads(item["details_json"])
            except json.JSONDecodeError:
                return {"ok": False, "checked": checked, "failed_seq": item["seq"], "reason": "Invalid details JSON"}
            payload = {
                "seq": item["seq"], "timestamp": item["timestamp"], "event": item["event"],
                "actor": item["actor"], "case_id": item["case_id"], "details": details,
            }
            expected = hashlib.sha256((previous + _canonical_json(payload)).encode("utf-8")).hexdigest()
            if item["prev_hash"] != previous or item["event_hash"] != expected:
                return {"ok": False, "checked": checked, "failed_seq": item["seq"], "reason": "Hash chain mismatch"}
            if item["event"] == "NOTE_ADDED":
                note_id = details.get("note_id")
                note = notes.get(note_id)
                if not note or not note["note_sha256"]:
                    return {"ok": False, "checked": checked, "failed_seq": item["seq"], "reason": "Investigator note missing or lacks integrity metadata"}
                live_note_hash = hashlib.sha256(note["note"].encode("utf-8")).hexdigest()
                if note["note_sha256"] != live_note_hash or details.get("note_sha256") != live_note_hash:
                    return {"ok": False, "checked": checked, "failed_seq": item["seq"], "reason": "Investigator note content mismatch"}
            previous = item["event_hash"]
            checked += 1
        return {"ok": True, "checked": checked, "last_hash": previous}

    def export_case_report(self, case_id: str, destination: str | Path) -> dict[str, Any]:
        """Export a structured case report locally; evidence file contents are not copied into the report."""
        case = self.case_summary(case_id)
        target = Path(destination).expanduser().resolve()
        vault_root = self.vault_dir.resolve()
        if target == self.db_path.resolve() or vault_root == target or vault_root in target.parents:
            raise ValueError("Choose a report destination outside the case database and evidence vault.")
        if target.exists():
            raise FileExistsError("Report destination already exists. Choose a new filename to avoid overwriting data.")

        evidence = []
        for item in self.list_evidence(case_id):
            evidence.append({
                key: item[key] for key in (
                    "evidence_id", "original_name", "sha256", "size_bytes", "media_type",
                    "source_label", "description", "collected_at", "added_by",
                )
            })
        report = {
            "report_schema": "cyberai.case-report.v2",
            "exported_at_utc": utc_now(),
            "case": case,
            "evidence": evidence,
            "indicators": self.list_indicators(case_id),
            "repeated_indicator_leads": self.correlations(case_id),
            "evidence_timeline": {
                **{key: value for key, value in self.evidence_timeline(case_id).items() if key != "events"},
                "events": [
                    {key: value for key, value in event.items() if not key.startswith("_")}
                    for event in self.evidence_timeline(case_id)["events"]
                ],
            },
            "investigator_notes": self.list_notes(case_id),
            "case_audit_timeline": self.timeline(case_id),
            "interpretation_guardrails": [
                "An indicator match is an investigative lead, not attribution to a person.",
                "A shared IP address or domain does not establish common ownership or intent.",
                "SHA-256 confirms the exported/stored copy matches the recorded digest, not source authenticity or legal admissibility.",
                "The report contains case metadata and analysis output, not the original evidence file contents.",
                "Evidence timeline timestamps are parsed from imported text only; missing timezone offsets remain unknown and can affect ordering.",
            ],
            "limitations": [
                "This report reflects only locally imported evidence and recorded notes at export time.",
                "No provider, telecom, finance, social platform, geolocation, or external threat-intelligence service was queried.",
                "The local audit chain is tamper-evident but not digitally signed.",
            ],
        }
        payload = (json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
        target.parent.mkdir(parents=True, exist_ok=True)
        temp = target.with_name(target.name + "." + uuid.uuid4().hex + ".tmp")
        try:
            with temp.open("xb") as stream:
                stream.write(payload)
            temp.replace(target)
        finally:
            temp.unlink(missing_ok=True)
        report_hash = hashlib.sha256(payload).hexdigest()
        with self._write() as con:
            self._event(con, "CASE_REPORT_EXPORTED", case_id, {
                "report_filename": target.name, "report_sha256": report_hash,
                "report_bytes": len(payload), "timeline_includes_export_event": False,
            })
        return {"case_id": case_id, "path": str(target), "sha256": report_hash, "size_bytes": len(payload)}

    def export_audit(self, destination: str | Path) -> int:
        target = Path(destination).expanduser()
        with closing(self._connect()) as con:
            rows = con.execute("SELECT * FROM audit_events ORDER BY seq").fetchall()
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("w", encoding="utf-8", newline="\n") as stream:
            for row in rows:
                stream.write(json.dumps(dict(row), ensure_ascii=False, sort_keys=True) + "\n")
        return len(rows)


class CaseworkWindow:
    """Tkinter casework front-end; the Store remains independently testable."""

    def __init__(self, master: Any, store: CaseStore | None = None):
        if tk is None or ttk is None:
            raise RuntimeError("Tkinter is unavailable.")
        self.store = store or CaseStore()
        self.window = tk.Toplevel(master)
        self.window.title("CYBERAI JARVIS | Case & Evidence Workbench")
        self.window.geometry("1180x760")
        self.window.minsize(1000, 640)
        self.window.configure(bg=BG)
        self.selected_case_id: str | None = None
        self._style()
        self._build()
        self.refresh_cases()

    def _style(self):
        style = ttk.Style(self.window)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Case.Treeview", background=PANEL, fieldbackground=PANEL, foreground=WHITE,
                        rowheight=24, borderwidth=0, font=("Consolas", 8))
        style.configure("Case.Treeview.Heading", background=PANEL_ALT, foreground=TEAL,
                        font=("Segoe UI", 8, "bold"), relief="flat", padding=(5, 5))
        style.map("Case.Treeview", background=[("selected", "#17414A")], foreground=[("selected", WHITE)])
        style.configure("Case.TNotebook", background=BG, borderwidth=0)
        style.configure("Case.TNotebook.Tab", background=PANEL_ALT, foreground=WHITE, padding=(10, 7))
        style.map("Case.TNotebook.Tab", background=[("selected", PANEL)], foreground=[("selected", TEAL)])

    def _label(self, parent: Any, text: str, color: str = WHITE, size: int = 9, bold: bool = False, **kwargs: Any):
        return tk.Label(parent, text=text, bg=parent.cget("bg"), fg=color,
                        font=("Segoe UI", size, "bold" if bold else "normal"),
                        anchor=kwargs.pop("anchor", "w"), **kwargs)

    def _button(self, parent: Any, text: str, command: Any, color: str = TEAL):
        return tk.Button(parent, text=text, command=command, bg=PANEL_ALT, fg=color,
                         activebackground="#17414A", activeforeground=WHITE, relief="flat",
                         bd=0, padx=9, pady=6, font=("Segoe UI", 8, "bold"), cursor="hand2")

    def _build(self):
        outer = tk.Frame(self.window, bg=BG, padx=12, pady=10)
        outer.pack(fill="both", expand=True)
        heading = tk.Frame(outer, bg=BG)
        heading.pack(fill="x", pady=(0, 8))
        left = tk.Frame(heading, bg=BG)
        left.pack(side="left", fill="x", expand=True)
        self._label(left, "CYBERAI  /  INVESTIGATION WORKBENCH", TEAL, 8, True).pack(anchor="w")
        self._label(left, "Case & Evidence Manager", WHITE, 18, True).pack(anchor="w", pady=(2, 0))
        self._label(left, "Local evidence vault • SHA-256 verification • correlated leads • audit chain", MUTED, 8).pack(anchor="w")
        self.integrity_label = self._label(heading, "● AUDIT CHECK PENDING", AMBER, 8, True)
        self.integrity_label.pack(side="right", anchor="center")
        actions = tk.Frame(outer, bg=BG)
        actions.pack(fill="x", pady=(0, 8))
        action_items = [
            ("+ NEW CASE", self.new_case, TEAL),
            ("IMPORT EVIDENCE", self.import_evidence, GREEN),
            ("ADD NOTE", self.add_note, WHITE),
            ("SET STATUS", self.set_status, AMBER),
            ("VERIFY HASHES", self.verify_hashes, CYAN),
            ("CORRELATIONS", self.show_correlations, TEAL),
            ("TIMELINE", self.show_timeline, WHITE),
            ("EVIDENCE TIMELINE", self.show_evidence_timeline, CYAN),
            ("EXPORT CASE REPORT", self.export_case_report, GREEN),
            ("EXPORT AUDIT", self.export_audit, VIOLET),
        ]
        for column in range(5):
            actions.grid_columnconfigure(column, weight=1, uniform="actions")
        for index, (label, command, color) in enumerate(action_items):
            self._button(actions, label, command, color).grid(
                row=index // 5, column=index % 5, sticky="ew", padx=2, pady=2,
            )
        body = tk.Frame(outer, bg=BG)
        body.pack(fill="both", expand=True)
        body.grid_columnconfigure(0, weight=3, uniform="columns")
        body.grid_columnconfigure(1, weight=8, uniform="columns")
        body.grid_rowconfigure(0, weight=1)
        case_panel = tk.Frame(body, bg=PANEL, padx=8, pady=8, highlightthickness=1, highlightbackground=EDGE)
        case_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        self._label(case_panel, "CASE REGISTER", TEAL, 9, True).pack(anchor="w", pady=(0, 6))
        self.case_tree = ttk.Treeview(case_panel, columns=("id", "status"), show="tree headings", style="Case.Treeview")
        self.case_tree.heading("#0", text="CASE TITLE")
        self.case_tree.column("#0", width=160, minwidth=110, anchor="w")
        self.case_tree.heading("id", text="CASE ID")
        self.case_tree.column("id", width=130, minwidth=95, anchor="w")
        self.case_tree.heading("status", text="STATUS")
        self.case_tree.column("status", width=115, minwidth=75, anchor="w")
        self.case_tree.pack(fill="both", expand=True)
        self.case_tree.bind("<<TreeviewSelect>>", self._on_select)
        self._label(case_panel, "Local-only • protect the evidence folder", MUTED, 7).pack(anchor="w", pady=(6, 0))

        right = tk.Frame(body, bg=BG)
        right.grid(row=0, column=1, sticky="nsew")
        right.grid_rowconfigure(1, weight=1)
        right.grid_columnconfigure(0, weight=1)
        self.case_heading = self._label(right, "Select or create a case", WHITE, 12, True)
        self.case_heading.grid(row=0, column=0, sticky="w", pady=(2, 7))
        self.notebook = ttk.Notebook(right, style="Case.TNotebook")
        self.notebook.grid(row=1, column=0, sticky="nsew")
        self.overview_tab = self._tab("OVERVIEW")
        self.evidence_tab = self._tab("EVIDENCE")
        self.indicators_tab = self._tab("INDICATORS")
        self.correlations_tab = self._tab("CORRELATIONS")
        self.timeline_tab = self._tab("TIMELINE & AUDIT")
        self.overview_text = self._text(self.overview_tab)
        self.evidence_tree = self._tree(self.evidence_tab, ("id", "name", "size", "hash", "source"))
        for key, label, width in [
            ("id", "EVIDENCE ID", 120), ("name", "FILENAME", 180), ("size", "SIZE", 70),
            ("hash", "SHA-256", 180), ("source", "PROVENANCE", 180),
        ]:
            self.evidence_tree.heading(key, text=label)
            self.evidence_tree.column(key, width=width, minwidth=60, anchor="w", stretch=True)
        self.evidence_tree.bind("<Double-1>", self._show_evidence_details)
        self.indicator_tree = self._tree(self.indicators_tab, ("type", "value", "evidence", "file"))
        for key, label, width in [("type", "TYPE", 100), ("value", "INDICATOR", 320), ("evidence", "EVIDENCE ID", 130), ("file", "SOURCE FILE", 230)]:
            self.indicator_tree.heading(key, text=label)
            self.indicator_tree.column(key, width=width, minwidth=70, anchor="w", stretch=True)
        self.correlation_tree = self._tree(self.correlations_tab, ("type", "value", "count", "files"))
        for key, label, width in [("type", "TYPE", 100), ("value", "REPEATED INDICATOR", 270), ("count", "FILES", 65), ("files", "MATCHED EVIDENCE", 240)]:
            self.correlation_tree.heading(key, text=label)
            self.correlation_tree.column(key, width=width, minwidth=70, anchor="w", stretch=True)
        self.timeline_tree = self._tree(self.timeline_tab, ("time", "event", "actor", "details"))
        for key, label, width in [("time", "UTC TIME", 170), ("event", "EVENT", 165), ("actor", "ACTOR", 100), ("details", "DETAILS", 320)]:
            self.timeline_tree.heading(key, text=label)
            self.timeline_tree.column(key, width=width, minwidth=70, anchor="w", stretch=True)
        self.status_bar = self._label(outer, "Ready. Evidence is copied into a local vault; source files are not modified.", MUTED, 7)
        self.status_bar.pack(fill="x", pady=(7, 0))

    def _tab(self, title: str):
        frame = tk.Frame(self.notebook, bg=PANEL, padx=10, pady=10)
        self.notebook.add(frame, text=title)
        return frame

    def _text(self, parent: Any):
        widget = tk.Text(parent, wrap="word", bg=PANEL, fg=WHITE, relief="flat", bd=0,
                         font=("Segoe UI", 9), insertbackground=TEAL)
        widget.pack(fill="both", expand=True)
        widget.configure(state="disabled")
        return widget

    def _tree(self, parent: Any, columns: tuple[str, ...]):
        frame = tk.Frame(parent, bg=PANEL)
        frame.pack(fill="both", expand=True)
        tree = ttk.Treeview(frame, columns=columns, show="headings", style="Case.Treeview")
        scroll = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scroll.set)
        tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        return tree

    def _set_text(self, widget: Any, value: str):
        widget.configure(state="normal")
        widget.delete("1.0", tk.END)
        widget.insert("1.0", value)
        widget.configure(state="disabled")

    def _selected(self) -> str | None:
        return self.selected_case_id

    def refresh_cases(self, select_case: str | None = None):
        cases = self.store.list_cases()
        for item in self.case_tree.get_children():
            self.case_tree.delete(item)
        for case in cases:
            self.case_tree.insert("", "end", iid=case["case_id"], text=case["title"],
                                  values=(case["case_id"], case["status"]))
        integrity = self.store.audit_integrity()
        self.integrity_label.configure(
            text=f"● AUDIT CHAIN {'VALID' if integrity['ok'] else 'CHECK FAILED'} · {integrity['checked']} EVENTS",
            fg=GREEN if integrity["ok"] else RED,
        )
        target = select_case or self.selected_case_id or (cases[0]["case_id"] if cases else None)
        if target and target in {c["case_id"] for c in cases}:
            self.case_tree.selection_set(target)
            self.case_tree.focus(target)
            self.selected_case_id = target
            self._load_case()
        else:
            self.selected_case_id = None
            self.case_heading.configure(text="Create a case to begin")
            self._set_text(self.overview_text, "No case selected.\n\nWorkflow:\n1. Create a case.\n2. Import a lawfully obtained local evidence file.\n3. Record its provenance and verify the stored SHA-256.\n4. Review repeated indicators and the audit timeline.\n\nThis tool produces investigative leads, not suspect attribution or legal conclusions.")
            self._clear_tree(self.evidence_tree)
            self._clear_tree(self.indicator_tree)
            self._clear_tree(self.correlation_tree)
            self._clear_tree(self.timeline_tree)

    def _clear_tree(self, tree: Any):
        for item in tree.get_children():
            tree.delete(item)

    def _on_select(self, _event=None):
        selection = self.case_tree.selection()
        if selection:
            self.selected_case_id = selection[0]
            self._load_case()

    def _load_case(self):
        case_id = self.selected_case_id
        if not case_id:
            return
        summary = self.store.case_summary(case_id)
        self.case_heading.configure(text=f"{summary['case_id']}  •  {summary['title']}")
        overview = (
            f"CASE STATUS: {summary['status']}\n"
            f"CREATED: {summary['created_at']}  (UTC)\n"
            f"UPDATED: {summary['updated_at']}  (UTC)\n"
            f"CREATED BY: {summary['created_by']}\n\n"
            f"DESCRIPTION\n{summary['description'] or 'No description recorded.'}\n\n"
            f"EVIDENCE ITEMS: {summary['evidence_count']}\n"
            f"EXTRACTED INDICATORS: {summary['indicator_count']}\n"
            f"REPEATED INDICATORS ACROSS FILES: {summary['correlation_count']}\n"
            f"INVESTIGATOR NOTES: {summary['note_count']}\n"
            + ("\n".join(f"• {note['created_at']} — {note['author']}: {note['note']}" for note in self.store.list_notes(case_id)[:8]) or "No notes recorded.") + "\n\n"
            "INTERPRETATION GUARDRAILS\n"
            "• Shared indicators are leads; shared IPs/domains do not prove a person is responsible.\n"
            "• Hash matches verify a stored copy against its recorded digest, not the truth of the source.\n"
            "• This app does not contact providers, locate devices, query external threat feeds or transmit evidence.\n"
        )
        self._set_text(self.overview_text, overview)
        self._clear_tree(self.evidence_tree)
        for ev in self.store.list_evidence(case_id):
            self.evidence_tree.insert("", "end", iid=ev["evidence_id"], values=(
                ev["evidence_id"], ev["original_name"], f"{ev['size_bytes']:,}",
                ev["sha256"][:16] + "…", ev["source_label"],
            ))
        self._clear_tree(self.indicator_tree)
        for item in self.store.list_indicators(case_id):
            self.indicator_tree.insert("", "end", values=(
                item["indicator_type"], item["value"], item["evidence_id"], item["original_name"],
            ))
        self._clear_tree(self.correlation_tree)
        for lead in self.store.correlations(case_id):
            self.correlation_tree.insert("", "end", values=(
                lead["indicator_type"], lead["value"], lead["evidence_count"],
                ", ".join(lead["filenames"])[:240],
            ))
        self._clear_tree(self.timeline_tree)
        for item in self.store.timeline(case_id):
            details = json.dumps(item["details"], ensure_ascii=False, sort_keys=True)
            self.timeline_tree.insert("", "end", values=(
                item["timestamp"], item["event"], item["actor"], details[:400],
            ))

    def _require_case(self) -> str | None:
        if not self.selected_case_id:
            messagebox.showinfo("Select case", "Create or select a case first.", parent=self.window)
            return None
        return self.selected_case_id

    def new_case(self):
        title = simpledialog.askstring("New case", "Case title:", parent=self.window)
        if title is None:
            return
        description = simpledialog.askstring("New case", "Brief description (optional):", parent=self.window) or ""
        try:
            case = self.store.create_case(title, description)
        except Exception as exc:
            messagebox.showerror("Could not create case", str(exc), parent=self.window)
            return
        self.refresh_cases(case["case_id"])
        self.status_bar.configure(text=f"Created {case['case_id']}.")

    def import_evidence(self):
        case_id = self._require_case()
        if not case_id:
            return
        filename = filedialog.askopenfilename(parent=self.window, title="Select local evidence file")
        if not filename:
            return
        source = simpledialog.askstring(
            "Evidence provenance",
            "Where did this file come from? (e.g. victim-provided email export, authorized lab log)",
            parent=self.window,
        )
        if source is None:
            return
        description = simpledialog.askstring("Evidence description", "Short note (optional):", parent=self.window) or ""
        try:
            item = self.store.add_evidence(case_id, filename, source, description)
        except Exception as exc:
            messagebox.showerror("Evidence import failed", str(exc), parent=self.window)
            return
        self._load_case()
        self.notebook.select(self.evidence_tab)
        self.status_bar.configure(text=f"Imported {item['evidence_id']} • SHA-256 {item['sha256']} • {item['indicator_count']} indicators extracted.")

    def add_note(self):
        case_id = self._require_case()
        if not case_id:
            return
        note = simpledialog.askstring("Investigator note", "Enter note or observation:", parent=self.window)
        if note is None:
            return
        try:
            self.store.add_note(case_id, note)
        except Exception as exc:
            messagebox.showerror("Could not add note", str(exc), parent=self.window)
            return
        self._load_case()
        self.notebook.select(self.timeline_tab)
        self.status_bar.configure(text="Note added to the case timeline.")

    def set_status(self):
        case_id = self._require_case()
        if not case_id:
            return
        status = simpledialog.askstring(
            "Case status",
            "Choose one status:\nOPEN\nINVESTIGATING\nAWAITING_LEGAL_PROCESS\nCLOSED",
            parent=self.window,
        )
        if status is None:
            return
        try:
            case = self.store.set_case_status(case_id, status)
        except Exception as exc:
            messagebox.showerror("Invalid status", str(exc), parent=self.window)
            return
        self.refresh_cases(case["case_id"])
        self.status_bar.configure(text=f"{case_id} status set to {case['status']}.")

    def _show_evidence_details(self, _event=None):
        selection = self.evidence_tree.selection()
        if not selection:
            return
        try:
            item = self.store.get_evidence(selection[0])
        except Exception as exc:
            messagebox.showerror("Evidence details", str(exc), parent=self.window)
            return
        messagebox.showinfo(
            "Evidence metadata",
            f"Evidence ID: {item['evidence_id']}\n"
            f"Filename: {item['original_name']}\n"
            f"SHA-256: {item['sha256']}\n"
            f"Size: {item['size_bytes']:,} bytes\n"
            f"Media type: {item['media_type']}\n"
            f"Collected (UTC): {item['collected_at']}\n"
            f"Provenance: {item['source_label']}\n"
            f"Description: {item['description'] or '(none)'}\n"
            f"Vault path: {item['absolute_path']}",
            parent=self.window,
        )

    def verify_hashes(self):
        case_id = self._require_case()
        if not case_id:
            return
        results = self.store.verify_case_evidence(case_id)
        matches = sum(item["status"] == "MATCH" for item in results)
        failures = len(results) - matches
        self._load_case()
        self.notebook.select(self.timeline_tab)
        messagebox.showinfo("Evidence integrity", f"Checked {len(results)} item(s).\nMatches: {matches}\nFailures/missing: {failures}\n\nThis verifies stored copies against recorded SHA-256 values; it does not validate source authenticity.", parent=self.window)
        self.status_bar.configure(text=f"Integrity check complete: {matches} match(es), {failures} issue(s).")

    def show_correlations(self):
        case_id = self._require_case()
        if not case_id:
            return
        self._load_case()
        self.notebook.select(self.correlations_tab)
        leads = self.store.correlations(case_id)
        if leads:
            self.status_bar.configure(text=f"{len(leads)} repeated indicator lead(s) across separate evidence files. Review context before drawing conclusions.")
        else:
            self.status_bar.configure(text="No repeated indicators across separate evidence files.")

    def show_timeline(self):
        case_id = self._require_case()
        if not case_id:
            return
        self._load_case()
        self.notebook.select(self.timeline_tab)

    def show_evidence_timeline(self):
        case_id = self._require_case()
        if not case_id:
            return
        try:
            analysis = self.store.evidence_timeline(case_id)
            rows: list[tuple[float, tuple[str, str, str, str]]] = []
            for item in self.store.timeline(case_id):
                try:
                    epoch = datetime.fromisoformat(item["timestamp"].replace("Z", "+00:00")).timestamp()
                except (TypeError, ValueError, OverflowError):
                    epoch = 0.0
                details = json.dumps(item["details"], ensure_ascii=False, sort_keys=True)
                rows.append((epoch, (
                    item["timestamp"], item["event"], item["actor"], details[:400],
                )))
            for event in analysis["events"]:
                shown_time = event["timestamp_utc"] or f"TZ UNKNOWN • {event['timestamp_raw']}"
                details = (
                    f"{event['filename']}:L{event['line_number']} • {event['timezone_status']} • "
                    f"{event['parser']} • {event['context']}"
                )
                if event["indicators"]:
                    labels = ", ".join(
                        f"{entry['indicator_type']}={entry['value']}" for entry in event["indicators"][:5]
                    )
                    details += f" • indicators: {labels}"
                rows.append((event["_sort_epoch"], (
                    shown_time, "EVIDENCE_TIMESTAMP", f"{event['evidence_id']}:L{event['line_number']}", details[:400],
                )))
            self._clear_tree(self.timeline_tree)
            for _epoch, values in sorted(rows, key=lambda row: row[0]):
                self.timeline_tree.insert("", "end", values=values)
            self.notebook.select(self.timeline_tab)
            self.status_bar.configure(
                text=(
                    f"Evidence timeline: {analysis['event_count']} timestamped event(s) from "
                    f"{analysis['evidence_files_scanned']} verified text file(s); "
                    f"{len(analysis['timeline_correlation_leads'])} cross-file lead(s), "
                    f"{len(analysis['warnings'])} warning(s). "
                    "Timezone-unknown rows have approximate ordering only."
                )
            )
        except Exception as exc:
            messagebox.showerror("Evidence timeline failed", str(exc), parent=self.window)

    def export_case_report(self):
        case_id = self._require_case()
        if not case_id:
            return
        destination = filedialog.asksaveasfilename(
            parent=self.window, title="Export structured case report",
            defaultextension=".json", filetypes=[("JSON report", "*.json"), ("All files", "*.*")],
            initialfile=f"{case_id}_report.json",
        )
        if not destination:
            return
        try:
            result = self.store.export_case_report(case_id, destination)
        except Exception as exc:
            messagebox.showerror("Case report export failed", str(exc), parent=self.window)
            return
        self.refresh_cases(case_id)
        messagebox.showinfo(
            "Case report exported",
            f"Report: {result['path']}\nSHA-256: {result['sha256']}\n"
            f"Size: {result['size_bytes']:,} bytes\n\n"
            "The report contains case metadata and analysis output, not original evidence contents. "
            "The export event is in the live audit log; the exported timeline is a snapshot from before that event.",
            parent=self.window,
        )
        self.status_bar.configure(text=f"Case report exported • SHA-256 {result['sha256']}")

    def export_audit(self):
        destination = filedialog.asksaveasfilename(
            parent=self.window, title="Export case audit chain",
            defaultextension=".jsonl", filetypes=[("JSON Lines", "*.jsonl"), ("All files", "*.*")],
        )
        if not destination:
            return
        try:
            count = self.store.export_audit(destination)
        except Exception as exc:
            messagebox.showerror("Audit export failed", str(exc), parent=self.window)
            return
        messagebox.showinfo("Audit exported", f"Exported {count} audit event(s).\nUse Audit Chain VALID to check the local event chain before export.", parent=self.window)
        self.status_bar.configure(text=f"Audit JSONL exported to {destination}.")


def open_casework(master: Any, data_dir: str | Path | None = None) -> CaseworkWindow:
    """Open the local casework workbench from the JARVIS dashboard."""
    return CaseworkWindow(master, CaseStore(data_dir=data_dir))
