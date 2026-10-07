"""The class hierarchy of the setup ontology, read from the `x-classes` table of the normative setup schema."""
import json
from pathlib import Path

SCHEMA = json.loads((Path(__file__).resolve().parent.parent.parent / "SetupOntology.schema.json").read_text(encoding="utf-8"))
TABLE = SCHEMA["x-classes"]

CLASSES = tuple(TABLE)
CONCRETE = tuple(c for c in CLASSES if not TABLE[c].get("abstract") and not TABLE[c].get("nested"))
COLLECTIONS = {c: TABLE[c]["collection"] for c in CLASSES if "collection" in TABLE[c]}
SUBCLASSES = {a: tuple(c for c in CLASSES if TABLE[c].get("parent") == a) for a in CLASSES if TABLE[a].get("abstract")}
# secrets that someone must hold or enter; a descriptor is only public data
CREDENTIALS = tuple(c for c in CLASSES if TABLE[c].get("credential"))
# classes whose plan entries say where they are kept
STORABLE = tuple(c for c, coll in COLLECTIONS.items()
                 if "stored_in" in SCHEMA["$defs"][SCHEMA["properties"][coll]["items"]["$ref"].rsplit("/", 1)[1]]["properties"])


def is_a(cls, ancestor):
    return cls == ancestor or cls in SUBCLASSES.get(ancestor, ())
