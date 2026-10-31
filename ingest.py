"""
PHASE 1 — INPUT & INGESTION LAYER
Accepts raw uploaded files (bytes + filename) and figures out what they are
before handing them to the parsing engine.
"""
from __future__ import annotations
import json
import uuid
from dataclasses import dataclass, field


@dataclass
class IngestedFile:
    file_id: str
    filename: str
    file_type: str      # "alert_json" | "raw_log" | "unknown"
    source: str          # best-guess agent/source name
    raw_text: str
    lines: list = field(default_factory=list)
    json_records: list = field(default_factory=list)


def _looks_like_json(text: str) -> bool:
    stripped = text.strip()
    if not stripped:
        return False
    first = stripped[0]
    return first in "{["


def _extract_json_records(text: str) -> list:
    """
    Wazuh/OSSEC alert files are frequently either:
      - a single JSON array
      - a JSON object per line (JSON-lines / alerts.json style)
    Handle both.
    """
    text = text.strip()
    records = []
    if not text:
        return records
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return [r for r in parsed if isinstance(r, dict)]
        if isinstance(parsed, dict):
            return [parsed]
    except json.JSONDecodeError:
        pass

    # fall back: JSON-lines
    for line in text.splitlines():
        line = line.strip().rstrip(",")
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                records.append(obj)
        except json.JSONDecodeError:
            continue
    return records


def _guess_source(filename: str, json_records: list, lines: list) -> str:
    if json_records:
        for r in json_records:
            agent = r.get("agent", {})
            if isinstance(agent, dict) and agent.get("name"):
                return agent["name"]
        first = json_records[0]
        if first.get("agent_name"):
            return first["agent_name"]
    return filename.rsplit(".", 1)[0]


def identify_and_load(filename: str, raw_bytes: bytes) -> IngestedFile:
    """Detect file type/format and produce an IngestedFile record."""
    try:
        text = raw_bytes.decode("utf-8", errors="replace")
    except Exception:
        text = raw_bytes.decode("latin-1", errors="replace")

    file_id = str(uuid.uuid4())[:8]
    lower_name = filename.lower()

    if lower_name.endswith(".json") or _looks_like_json(text):
        records = _extract_json_records(text)
        file_type = "alert_json" if records else "unknown"
        source = _guess_source(filename, records, [])
        return IngestedFile(
            file_id=file_id, filename=filename, file_type=file_type,
            source=source, raw_text=text, json_records=records,
        )

    # otherwise treat as raw log (.log, .txt, or anything unrecognized)
    lines = [l for l in text.splitlines() if l.strip()]
    return IngestedFile(
        file_id=file_id, filename=filename, file_type="raw_log",
        source=filename.rsplit(".", 1)[0], raw_text=text, lines=lines,
    )


def ingest_many(files: list[tuple[str, bytes]]) -> list[IngestedFile]:
    """files: list of (filename, raw_bytes)"""
    return [identify_and_load(name, data) for name, data in files]
