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
DATA = ENGINE.parent                 # catalogs, ratings, schemas
ONTOLOGY = DATA.parent               # setup schema and ontology
LOOKUPS = ONTOLOGY / "Lookups"

CATALOG_FILES = {
    "threats": ("Threats.json", "Threats.schema.json"),
    "mechanisms": ("Mechanisms.json", "Mechanisms.schema.json"),
    "actions": ("RecoveryActions.json", "RecoveryActions.schema.json"),
    "ratings": ("Ratings.json", "Ratings.schema.json"),
    "common_cause": ("CommonCause.json", "CommonCause.schema.json"),
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
    """Errors of `instance` against a schema file name; schemas may reference each other."""
    store = schema_store()
    schema = store[schema_name]
    validator = Draft202012Validator(schema, resolver=RefResolver.from_schema(schema, store=store))
    errors = []
    for e in sorted(validator.iter_errors(instance), key=lambda e: [str(x) for x in e.absolute_path]):
        errors.append("/".join(str(x) for x in e.absolute_path) + ": " + e.message[:200])
    return errors


def csv_rows(path, key_columns):
    rows = {}
    with open(path, encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            rows[tuple(row[c] for c in key_columns)] = row
    return rows


class Catalogs:
    """All static data: threat, mechanism and action catalogs, rating tables, lookup tables."""

    def __init__(self):
        self.raw = {name: read_json(DATA / f) for name, (f, _) in CATALOG_FILES.items()}
        self.threats = {t["id"]: t for t in self.raw["threats"]["threats"]}
        self.mechanisms = {m["id"]: m for m in self.raw["mechanisms"]["mechanisms"]}
        self.actions = {a["id"]: a for a in self.raw["actions"]["actions"]}
        self.ratings = self.raw["ratings"]
        self.category_likelihood = self.raw["threats"]["category_likelihood"]
        self.common_cause = self.raw["common_cause"]["groups"]
        self.device_rows = csv_rows(LOOKUPS / "SigningDeviceCatalog.csv", ("vendor", "model"))
        self.metal_rows = csv_rows(LOOKUPS / "MetalBackupCatalog.csv", ("vendor", "model"))
        self.location_rows = csv_rows(LOOKUPS / "LocationKinds.csv", ("kind",))
        self.responded = {t for a in self.actions.values() for t in a.get("responds_to", [])}

    def hashes(self):
        h = {name: sha(DATA / f) for name, (f, _) in CATALOG_FILES.items()}
        for name, f in (("device_catalog", "SigningDeviceCatalog.csv"), ("metal_catalog", "MetalBackupCatalog.csv"), ("location_kinds", "LocationKinds.csv")):
            h[name] = sha(LOOKUPS / f)
        return h

    def has_response(self, threat_id):
        return threat_id in self.responded


def check_catalogs(cat, predicate_names):
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
        pred = m.get("predicate", {}).get("name")
        if pred and pred not in predicate_names:
            errors.append(f"mechanism {m['id']}: predicate {pred} is not implemented")
    for a in cat.actions.values():
        for t in a.get("responds_to", []):
            if t not in cat.threats:
                errors.append(f"action {a['id']}: unknown threat {t}")
        for s in a.get("steps", []):
            if s["action"] not in cat.actions:
                errors.append(f"action {a['id']}: unknown step {s['action']}")
    for t in cat.threats.values():
        pred = t.get("predicate", {}).get("name")
        if pred and pred not in predicate_names:
            errors.append(f"threat {t['id']}: predicate {pred} is not implemented")
    errors += check_classes(cat)
    errors += check_location_kinds(cat)
    errors += [f"threats: no default likelihood for the category {c}" for c in vocab.CATEGORIES if c not in cat.category_likelihood]
    for g in cat.common_cause:
        for tid in g["threats"]:
            if tid not in cat.threats:
                errors.append(f"common cause: unknown threat {tid}")
    return errors


def check_location_kinds(cat):
    """The kinds a plan may use and the rows of the lookup table must be the same, apart from the kinds the tool makes itself."""
    allowed = set(ontology.SCHEMA["$defs"]["location"]["properties"]["kind"]["enum"])
    rows = {k for (k,), row in cat.location_rows.items() if row["origin"] == "plan"}
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


def preflight(data, cat):
    """Schema validation and referential checks of a setup. Returns (errors, warnings)."""
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

    for loc in data.get("locations", []):
        if "access" not in loc:
            warnings.append(f"location {loc['id']}: no access list; nobody can reach it")
    for d in data.get("devices", []):
        w = f"device {d['id']}"
        if (d["vendor"], d["model"]) not in cat.device_rows:
            warnings.append(f"{w}: {d['vendor']} / {d['model']} is not in the device catalog")
    for d in data.get("computing_devices", []):
        w = f"computing device {d['id']}"
        if d["kind"] == "mobile" and "person" not in d["stored_in"]:
            errors.append(f"{w}: a mobile device is carried by a person; use stored_in person")
        if d["kind"] == "desktop" and "person" in d["stored_in"]:
            errors.append(f"{w}: a desktop computer stands in a location, it is not carried")
    for w in data["wallets"]:
        for p in w["spending_policies"]:
            if p["threshold"] > len(p["signers"]):
                errors.append(f"wallet {w['id']}: threshold {p['threshold']} exceeds {len(p['signers'])} signers")
    held = {b_item["subject"]["descriptor"] for b in data.get("backups", []) for b_item in b["items"] if "descriptor" in b_item["subject"]}
    held |= {x for coll in ("devices", "computing_devices", "coordinators") for d in data.get(coll, []) for x in d.get("stores_descriptors", [])}
    descriptors_of = {}
    for d in data.get("descriptors", []):
        descriptors_of.setdefault(d["wallet"], []).append(d["id"])
        if d["id"] not in held:
            errors.append(f"descriptor {d['id']}: kept nowhere; it needs a backup copy, a registration on a device or a coordinator that has it")
    for w in data["wallets"]:
        signers = {(sg["seed"], sg.get("passphrase")) for pol in w["spending_policies"] for sg in pol["signers"]}
        mine = descriptors_of.get(w["id"], [])
        if len(mine) > 1:
            errors.append(f"wallet {w['id']} has {len(mine)} descriptors; a wallet has at most one")
        if (w.get("definition") == "custom" or len(signers) > 1) and not mine:
            errors.append(f"wallet {w['id']} has several signers or a custom definition and needs a descriptor")
    for b in data.get("backups", []):
        where = f"backup {b['id']}"
        if b["medium"] == "memory" and "person" not in b["stored_in"]:
            errors.append(f"{where}: a memory backup is in a person's mind; use stored_in person")
        if "product" in b and (b["product"]["vendor"], b["product"]["model"]) not in cat.metal_rows:
            warnings.append(f"{where}: product {b['product']['vendor']} / {b['product']['model']} is not in the backup catalog")
    # access rights
    mains = [w["id"] for w in data["wallets"] if not w.get("tripwire", {}).get("enabled")]
    declared = {}
    for p in data.get("people", []):
        where = f"person {p['id']} may_spend"
        for e in p.get("may_spend", []):
            if p["id"] in e.get("with", []):
                errors.append(f"{where}: the person is listed in their own `with`")
            for w in e.get("wallets", mains):
                declared.setdefault((frozenset([p["id"], *e.get("with", [])]), w), set()).add(e.get("after_blocks", 0))
    for (people, w), delays in declared.items():
        if len(delays) > 1:
            errors.append(f"may_spend: {' and '.join(sorted(people))} are given different delays for {w}: {sorted(delays)}")
    for w in mains:
        if not any(k[1] == w for k in declared):
            errors.append(f"wallet {w}: nobody may spend it; give a person a `may_spend` entry")
    # bag cycles
    bag_in = {b["id"]: b["stored_in"].get("bag") for b in data.get("bags", [])}
    for start in bag_in:
        seen, cur = set(), start
        while cur:
            if cur in seen:
                errors.append(f"bag cycle at {start}")
                break
            seen.add(cur)
            cur = bag_in.get(cur)
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
        allowed = ontology.SUBCLASSES.get(m["target"], (m["target"],))
        for ref in p.get("scope", []):
            if ref not in cls and ref != "@plan":
                errors.append(f"{where}: unknown id {ref}")
            elif ref in cls and cls[ref] not in allowed:
                errors.append(f"{where}: {ref} is a {cls[ref]}, but {p['mechanism']} targets {m['target']}")
    # secrets without any copy
    held = set()
    for b in data.get("backups", []):
        for item in b["items"]:
            held.update(v for k, v in item["subject"].items() if k != "plan")
    for coll in ("seeds", "passphrases", "pins"):
        for s in data.get(coll, []):
            if s["id"] not in held:
                warnings.append(f"{coll[:-1]} {s['id']} has no backup copy")
    if not errors:
        import predicates
        from model import Setup
        S = Setup(data, cat)
        for w in S.ids_of("Wallet"):
            if not S.coordinators_of(w):
                warnings.append(f"wallet {w}: no coordinator has its descriptor, so nobody can build transactions for it; list the descriptor in `stores_descriptors` of a coordinator")
        for c in S.of("Coordinator"):
            if not S.ent(c["runs_on"])["online"]:
                warnings.append(f"coordinator {c['id']} runs on {c['runs_on']}, which is offline; a coordinator queries the network")
        for d in S.of("SigningDevice"):
            support, stored = S.registration_support(d["id"]), d.get("stores_descriptors", [])
            name, wallets = f"device {d['id']} ({d['vendor']} {d['model']})", S.registration_wallets(d["id"])
            if stored and support in ("none", "per_transaction"):
                errors.append(f"{name} cannot keep a registered descriptor (catalog: {support})")
            elif wallets and support == "unknown":
                warnings.append(f"{name} signs for {', '.join(wallets)}; the catalog does not say whether it registers descriptors, so it counts as not registering")
            elif wallets and support == "per_transaction":
                loads = any(p["mechanism"] == "M-P-LOAD-DESCRIPTOR" and (not p.get("scope") or d["id"] in p["scope"])
                            for p in data.get("practices", []))
                if not (loads and predicates.REGISTRY["descriptor_at_device_location"](S, d["id"])):
                    warnings.append(f"{name} signs for {', '.join(wallets)} and needs the descriptor loaded for every signing instead of a registered one; it counts as not checking the policy unless the descriptor is kept where the device is and a practice M-P-LOAD-DESCRIPTOR covers it")
            elif wallets and support != "registers":
                warnings.append(f"{name} signs for {', '.join(wallets)} but does not keep a registered descriptor (catalog: {support}); it cannot check the wallet policy before signing")
            else:
                missing = [w for w in wallets if S.ent(w).get("descriptor") not in stored]
                if missing:
                    warnings.append(f"{name} supports registering descriptors but has none registered for {', '.join(missing)}")
        places = [l["id"] for l in S.of("Location") if not l.get("part_of") and l["kind"] not in ("cloud", "person")]
        declared = {frozenset((S.root(t["from"]), S.root(t["to"]))) for t in data.get("travel_times", [])}
        absent = [f"{a} and {b}" for a, b in combinations(places, 2) if frozenset((a, b)) not in declared]
        if absent:
            warnings.append("no travel time between " + "; ".join(absent[:4]) + (f" and {len(absent) - 4} more pairs" if len(absent) > 4 else "") + "; they count as 0 minutes")
    return errors, warnings
