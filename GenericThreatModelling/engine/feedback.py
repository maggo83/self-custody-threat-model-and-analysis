"""Judgement that a person adds to an analysis, in one form: an override sets a rating. It names one of
  - a line of the analysis (`row`),
  - a threat on all entities (`threat`),
  - all threats on one entity (`entity`): any of L, V, S, the final value,
  - a question for the owners (`ask`, field L: the base likelihood of every threat the question concerns, before the
    modifiers).
Where several apply to one line, the line wins over the threat and the threat over the entity. A reason is always required. The overrides live in the
analysis file, are carried over when it is written again, and never touch the catalogs."""
import json
from pathlib import Path

FIELDS = ("L", "V", "S")
SCOPES = ("row", "threat", "entity")


def empty():
    return {"overrides": []}


def scope_of(o):
    names = [k for k in SCOPES + ("ask",) if k in o]
    return names[0] if len(names) == 1 else None


def key(o):
    k = scope_of(o)
    return (k, o.get(k), o.get("field")) if k else ("?", str(sorted(o)), o.get("field"))


def read(path):
    """Overrides of an existing analysis (or exported) file; nothing if there is none. Answers of an older format count as overrides."""
    path = Path(path)
    if not path.exists():
        return empty()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        return empty()
    old = [{"ask": a["ask"], "field": "L", "value": a["value"], "reason": a.get("note") or "answer to the question"}
           for a in data.get("answers", []) if "ask" in a and "value" in a]
    return {"overrides": list(data.get("overrides", [])) + old}


def merge(base, extra):
    """`extra` replaces the entries of `base` for the same line and field, or the same question."""
    merged = {key(o): o for o in base["overrides"]}
    merged.update({key(o): o for o in extra["overrides"]})
    return {"overrides": sorted(merged.values(), key=lambda o: tuple(map(str, key(o))))}


KEYS = SCOPES + ("ask", "field", "value", "reason", "by", "date", "setup_sha")


def clean(o):
    """Only the known keys of an entry that came from outside."""
    return {k: o[k] for k in KEYS if k in o} if isinstance(o, dict) else {}


def check(fb):
    """Error texts for entries that cannot be used."""
    errors = []
    for o in fb["overrides"]:
        scope = scope_of(o)
        who = o.get(scope) if scope else "?"
        if not scope:
            errors.append(f"override {who}: name exactly one of a line (row), a threat (threat), an entity (entity) or a question (ask)")
        elif scope == "ask" and o.get("field") != "L":
            errors.append(f"override of question \"{who}\": only the likelihood (L) can be set")
        elif o.get("field") not in FIELDS:
            errors.append(f"override {who}: the field must be L, V or S")
        if not isinstance(o.get("value"), int) or isinstance(o.get("value"), bool) or not 0 <= o["value"] <= 4:
            errors.append(f"override {who}: the value must be 0 to 4")
        if not str(o.get("reason", "")).strip():
            errors.append(f"override {who} {o.get('field')}: a reason is required")
    return errors


def by_scope(fb):
    """{scope: {name: {field: override}}} for the scopes row, threat and entity."""
    out = {k: {} for k in SCOPES}
    for o in fb["overrides"]:
        k = scope_of(o)
        if k in out:
            out[k].setdefault(o[k], {})[o["field"]] = o
    return out


def pick(scopes, row_id, threat, entities, field):
    """The override that rates this line: the line itself, else its threat, else the first of its entities that has one."""
    found = scopes["row"].get(row_id, {}).get(field) or scopes["threat"].get(threat, {}).get(field)
    for e in entities:
        found = found or scopes["entity"].get(e, {}).get(field)
    return found


def by_ask(fb):
    return {o["ask"]: o for o in fb["overrides"] if "ask" in o}


def stale(fb, rows, asks, setup_sha):
    """Warnings for overrides that name something that does not exist any more or were given for another version of the setup."""
    ids = {r["id"] for r in rows}
    threats = {r["threat"] for r in rows}
    entities = {e for r in rows for e in (r["entity"] if isinstance(r["entity"], list) else [r["entity"]])}
    known = {"row": ids, "threat": threats, "entity": entities}
    out = []
    for o in fb["overrides"]:
        k = scope_of(o)
        if k == "ask":
            if o["ask"] not in asks:
                out.append(f"the override of the question \"{o['ask']}\" belongs to a question that is no longer asked")
        elif k and o[k] not in known[k]:
            out.append(f"override of {o[k]} {o['field']} names a {'line' if k == 'row' else k} that does not exist and is ignored")
        elif k and o.get("setup_sha") and o["setup_sha"] != setup_sha:
            out.append(f"override of {o[k]} {o['field']} was given for an earlier version of the setup: check that it still holds")
    return out


def override(rating, o):
    """A rating dict with the value set by hand; the computed value stays visible."""
    note = {k: o[k] for k in ("reason", "by", "date") if k in o}
    if scope_of(o) in ("threat", "entity"):
        note["scope"] = scope_of(o)
        note["named"] = o[scope_of(o)]
    return dict(rating, value=o["value"], computed=rating["value"], override=note)
