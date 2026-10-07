"""Loading of schemas, catalogs and lookup tables, schema validation and preflight checks."""
import csv
import hashlib
import json
import re
from itertools import combinations
from pathlib import Path

from jsonschema import Draft202012Validator, RefResolver

import ontology
import vocab

ENGINE = Path(__file__).resolve().parent
ONTOLOGY = ontology.ROOT               # setup schema and ontology (CUSTODY_DATA_ROOT or the repository)
DATA = ONTOLOGY / "GenericThreatModelling"   # catalogs, ratings, schemas
LOOKUPS = ONTOLOGY / "Lookups"

CATALOG_FILES = {
    "threats": ("Threats.json", "Threats.schema.json"),
    "mechanisms": ("Mechanisms.json", "Mechanisms.schema.json"),
    "actions": ("RecoveryActions.json", "RecoveryActions.schema.json"),
    "ratings": ("Ratings.json", "Ratings.schema.json"),
    "common_cause": ("CommonCause.json", "CommonCause.schema.json"),
    "access": ("AccessModel.json", "AccessModel.schema.json"),
}
SETUP_SCHEMA = "SetupOntology.schema.json"


def read_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()[:12]


_store = {}


def schema_store():
    if not _store:
        for folder in (DATA, ONTOLOGY):
            for p in folder.glob("*.schema.json"):
                s = read_json(p)
                _store[p.name] = s
                if "$id" in s:
                    _store[s["$id"]] = s
    return _store


def validate(instance, schema_name):
    """Errors of `instance` against a schema file name; schemas may reference each other. A failed rule whose schema
    (or an enclosing `then`) carries an `x-message` reports that message instead of the generic one."""
    store = schema_store()
    schema = store[schema_name]
    validator = Draft202012Validator(schema, resolver=RefResolver.from_schema(schema, store=store))
    errors = []
    for e in sorted(validator.iter_errors(instance), key=lambda e: [str(x) for x in e.absolute_path]):
        errors.append("/".join(str(x) for x in e.absolute_path) + ": " + (_message(schema, e.absolute_schema_path) or e.message[:200]))
    return errors


def _message(schema, path):
    """The deepest `x-message` on the schema path of an error."""
    node, found = schema, None
    for key in path:
        if isinstance(node, dict) and "$ref" in node and key not in node:
            node = schema["$defs"][node["$ref"].rsplit("/", 1)[1]]
        try:
            node = node[key]
        except (KeyError, IndexError, TypeError):
            return found
        if isinstance(node, dict) and "x-message" in node:
            found = node["x-message"]
    return found


def csv_rows(path, key_columns):
    rows = {}
    with open(path, encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            rows[tuple(row[c] for c in key_columns)] = row
    return rows


class Catalogs:
    """All static data: threat, mechanism and action catalogs, rating tables, the access model, lookup tables."""

    def __init__(self, data_dir=None, lookups_dir=None):
        self.data_dir, self.lookups_dir = Path(data_dir or DATA), Path(lookups_dir or LOOKUPS)
        self.raw = {name: read_json(self.data_dir / f) for name, (f, _) in CATALOG_FILES.items()}
        self.threats = {t["id"]: t for t in self.raw["threats"]["threats"]}
        self.mechanisms = {m["id"]: m for m in self.raw["mechanisms"]["mechanisms"]}
        self.actions = {a["id"]: a for a in self.raw["actions"]["actions"]}
        self.ratings = self.raw["ratings"]
        self.access = self.raw["access"]
        self.category_likelihood = self.raw["threats"]["category_likelihood"]
        self.common_cause = self.raw["common_cause"]["groups"]
        self._lookups = {}
        self.responded = {t for a in self.actions.values() for t in a.get("responds_to", [])}

    def lookup(self, table):
        """Rows of a lookup table by key, the key columns being those the ontology declares for the class."""
        if table not in self._lookups:
            spec = next(c["catalog"] for c in ontology.TABLE.values() if c.get("catalog", {}).get("table") == table)
            columns = tuple(k.rsplit(".", 1)[-1] for k in spec["key"])
            self._lookups[table] = csv_rows(self.lookups_dir / table, columns)
        return self._lookups[table]

    @property
    def device_rows(self):
        return self.lookup("SigningDeviceCatalog.csv")

    @property
    def metal_rows(self):
        return self.lookup("MetalBackupCatalog.csv")

    @property
    def location_rows(self):
        return self.lookup("LocationKinds.csv")

    def hashes(self):
        h = {name: sha(self.data_dir / f) for name, (f, _) in CATALOG_FILES.items()}
        for c in ontology.TABLE.values():
            if "catalog" in c:
                h[c["catalog"]["table"]] = sha(self.lookups_dir / c["catalog"]["table"])
        return h

    def has_response(self, threat_id):
        return threat_id in self.responded


def check_catalogs(cat):
    """Schema and cross-reference errors of the static data (empty list = fine)."""
    errors = []
    for name, (_, schema) in CATALOG_FILES.items():
        errors += [f"{name}: {e}" for e in validate(cat.raw[name], schema)]
    for m in cat.mechanisms.values():
        for a in m.get("addresses", []):
            if a["threat"] not in cat.threats:
                errors.append(f"mechanism {m['id']}: unknown threat {a['threat']}")
        for p in m.get("procedure", []):
            if p not in cat.actions:
                errors.append(f"mechanism {m['id']}: unknown action {p}")
        if m.get("refines") and cat.mechanisms.get(m["refines"], {}).get("form") != "principle":
            errors.append(f"mechanism {m['id']}: refines {m['refines']}, which is not a principle")
    for a in cat.actions.values():
        for t in a.get("responds_to", []):
            if t not in cat.threats:
                errors.append(f"action {a['id']}: unknown threat {t}")
        for s in a.get("steps", []):
            if s["action"] not in cat.actions:
                errors.append(f"action {a['id']}: unknown step {s['action']}")
    for t in cat.threats.values():
        for impact in t["impacts"]:
            if impact["on"] not in cat.access["selectors"]:
                errors.append(f"threat {t['id']}: unknown impact selector {impact['on']}")
    for g in cat.access["goals"].values():
        if g["action"] not in cat.actions:
            errors.append(f"access model: goal names the unknown action {g['action']}")
    for key in cat.access["derived"]:
        if key.split(".")[0] not in ontology.CLASSES:
            errors.append(f"access model: derived attribute {key} names an unknown class")
    errors += check_classes(cat)
    errors += check_location_kinds(cat)
    errors += [f"threats: no default likelihood for the category {c}" for c in vocab.CATEGORIES if c not in cat.category_likelihood]
    for g in cat.common_cause:
        for tid in g["threats"]:
            if tid not in cat.threats:
                errors.append(f"common cause: unknown threat {tid}")
    return errors


def check_location_kinds(cat):
    """The kinds a plan may use and the rows of the lookup table must be the same."""
    allowed = set(ontology.SCHEMA["$defs"]["location"]["properties"]["kind"]["enum"])
    rows = {k for (k,) in cat.location_rows}
    return [f"location kinds: {k} is in only one of the setup schema and LocationKinds.csv" for k in sorted(allowed ^ rows)]


def check_classes(cat):
    """Class names of the catalogs that the ontology does not know."""
    errors = []

    def known(where, name, extra=()):
        if name not in ontology.CLASSES and name not in extra:
            errors.append(f"{where}: unknown class {name}")
    for t in cat.threats.values():
        for name in [t["target"]["class"], *t["target"].get("subclasses", [])]:
            known(f"threat {t['id']}", name)
    for m in cat.mechanisms.values():
        if "target" in m:
            known(f"mechanism {m['id']}", m["target"])
    for a in cat.actions.values():
        for p in a.get("params", []):
            known(f"action {a['id']}", p["class"], ("Number",))
    for g in cat.common_cause:
        known("common cause", g["class"])
    return errors


def references(data):
    """(where, id, class) for every id the plan points to; the classes come from the x-ref marks of the setup schema."""
    defs, label = ontology.SCHEMA["$defs"], {coll: re.sub(r"(?<=[a-z])(?=[A-Z])", " ", c).lower() for c, coll in ontology.COLLECTIONS.items()}

    def walk(value, node, where):
        if "x-ref" in node:
            for ref in [value] if isinstance(value, str) else value:
                yield where, ref, node["x-ref"]
            return
        if "$ref" in node:
            yield from walk(value, defs[node["$ref"].rsplit("/", 1)[1]], where)
            return
        for branch in node.get("oneOf", []) + node.get("anyOf", []):
            yield from walk(value, branch, where)
        if isinstance(value, dict):
            for key, sub in node.get("properties", {}).items():
                if key in value:
                    yield from walk(value[key], sub, where)
        elif isinstance(value, list) and "items" in node:
            for v in value:
                yield from walk(v, node["items"], where)
    for coll, node in ontology.SCHEMA["properties"].items():
        for item in data.get(coll, []) if node.get("type") == "array" else []:
            yield from walk(item, node["items"], f"{label.get(coll, coll.replace('_', ' '))} {item.get('id', '')}".strip())


def message(S, eid, text):
    """Fill `{path}` placeholders of a check message with the values of the entity."""
    def fill(m):
        vals = S.values(eid, m.group(1))
        return ", ".join(str(v) for v in vals) if vals else "?"
    return re.sub(r"\{([a-zA-Z_][a-zA-Z0-9_.\[\]]*)\}", fill, text)


def preflight(data, cat):
    """Schema validation, referential checks and the checks of the access model. Returns (errors, warnings)."""
    errors = [f"schema: {e}" for e in validate(data, SETUP_SCHEMA)]
    warnings = []
    if errors:
        return errors, warnings

    cls = {}
    for c, coll in ontology.COLLECTIONS.items():
        for e in data.get(coll, []):
            if e["id"] in cls:
                errors.append(f"duplicate id {e['id']}")
            cls[e["id"]] = c
    for where, ref, expected in references(data):
        if ref not in cls:
            errors.append(f"{where}: unknown id {ref}")
        elif not ontology.is_a(cls[ref], expected):
            errors.append(f"{where}: {ref} is a {cls[ref]}, expected {expected}")
    if errors:
        return errors, warnings

    from graph import Setup
    S = Setup(data, cat)
    # containment cycles
    for eid in S.by_id:
        chain, cur = [], S.container(eid)
        while cur and cur not in chain:
            chain.append(cur)
            cur = S.container(cur)
        if cur:
            errors.append(f"containment cycle at {eid}")
    if errors:
        return errors, warnings
    # the declared checks
    for check in cat.access.get("checks", []):
        for eid in S.ids_of(check["class"]):
            if S.holds(eid, check["when"]):
                (errors if check["level"] == "error" else warnings).append(message(S, eid, check["message"]))
    # access rights that contradict each other
    a = cat.access["actor"]
    declared = {}
    mains = [w for w in S.ids_of(cat.access["asset"]["class"]) if S.holds(w, cat.access["asset"]["main_when"])]
    for p in S.of(a["class"]):
        for e in p.get(a["rights"], []):
            for w in e.get(a["assets"], mains):
                declared.setdefault((frozenset([p["id"], *e.get(a["with"], [])]), w), set()).add(e.get(a["after"], 0))
    for (people, w), delays in declared.items():
        if len(delays) > 1:
            errors.append(f"{a['rights']}: {' and '.join(sorted(people))} are given different delays for {w}: {sorted(delays)}")
    # practices
    for p in data.get("practices", []):
        where = f"practice {p['id']}"
        m = cat.mechanisms.get(p["mechanism"])
        if not m:
            errors.append(f"{where}: unknown mechanism {p['mechanism']}")
            continue
        if m["form"] != "procedural":
            errors.append(f"{where}: {p['mechanism']} is not a procedural mechanism")
            continue
        for ref in p.get("scope", []):
            if ref not in S.by_id:
                errors.append(f"{where}: unknown id {ref}")
            elif not ontology.is_a(S.cls(ref), m["target"]):
                errors.append(f"{where}: {ref} is a {S.cls(ref)}, but {p['mechanism']} targets {m['target']}")
    # travel times
    spec = cat.access.get("travel", {})
    places = [l for l in S.places if ontology.is_a(S.cls(l), spec.get("between", "Location")) and not S.container(l) and not S.no_travel(l)]
    declared = {frozenset((S.root(t["from"]), S.root(t["to"]))) for t in data.get("travel_times", [])}
    absent = [f"{a} and {b}" for a, b in combinations(sorted(places), 2) if frozenset((a, b)) not in declared]
    if absent:
        warnings.append("no travel time between " + "; ".join(absent[:4]) + (f" and {len(absent) - 4} more pairs" if len(absent) > 4 else "") + "; they count as 0 minutes")
    return errors, warnings
