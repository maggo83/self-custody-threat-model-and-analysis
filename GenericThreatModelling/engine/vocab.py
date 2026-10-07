"""The vocabulary of the threat catalogs, read from the shared definitions of ThreatModelCommon.schema.json."""
import json

import ontology

DEFS = json.loads((ontology.ROOT / "GenericThreatModelling" / "ThreatModelCommon.schema.json").read_text(encoding="utf-8"))["$defs"]

CATEGORIES = tuple(DEFS["category"]["enum"])
KINDS = tuple(DEFS["impactKind"]["enum"])
LEAK = tuple(DEFS["impactKind"]["x-leak"])
MALICIOUS_SOURCES = frozenset(DEFS["source"]["x-malicious"])
