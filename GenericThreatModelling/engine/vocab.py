"""The vocabulary of the threat catalogs, read from the shared definitions of ThreatModelCommon.schema.json."""
import json
from pathlib import Path

DEFS = json.loads((Path(__file__).resolve().parent.parent / "ThreatModelCommon.schema.json").read_text(encoding="utf-8"))["$defs"]

CATEGORIES = tuple(DEFS["category"]["enum"])
SELECTORS = tuple(DEFS["impactOn"]["enum"])
KINDS = tuple(DEFS["impactKind"]["enum"])
LEAK = tuple(DEFS["impactKind"]["x-leak"])
MALICIOUS_SOURCES = frozenset(DEFS["source"]["x-malicious"])
