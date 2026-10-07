"""What-if on the procedural measures: what each practice in place is worth, what a wider scope would add,
and what a missing measure would add. Every figure is the risk of the same rows, rated again."""
import rating


def _index(S, cat, practices, implicit=True):
    saved = S.data.get("practices")
    S.data["practices"] = practices
    try:
        return rating.mechanism_instances(S, cat, implicit)
    finally:
        if saved is None:
            del S.data["practices"]
        else:
            S.data["practices"] = saved


def _entities(index, mid):
    return sorted({i["entity"] for insts in index.values() for i in insts if i["mechanism"] == mid})


def _changes(kept, index, rerate):
    """[row id, risk now, risk with this index, vulnerability now, vulnerability with it] for every row where one differs."""
    out = []
    for row, item in kept:
        if row["S"]["value"] == 0:
            continue
        v, r = rerate(item, index)
        if (v, r) != (row["V"]["value"], row["R"]):
            out.append([row["id"], row["R"], r, row["V"]["value"], v])
    return out


def measures(S, cat, kept, rerate):
    """One entry per procedural mechanism that is in place (by a practice or by the way the entity is used) or applicable to some entity."""
    practices = S.data.get("practices", [])
    out = []
    for mid, m in cat.mechanisms.items():
        if m["form"] != "procedural":
            continue
        mine = [p for p in practices if p["mechanism"] == mid]
        everywhere = _entities(_index(S, cat, [{"id": "what-if", "mechanism": mid}]), mid)
        if not everywhere:
            continue
        by_use = _entities(_index(S, cat, []), mid)
        if by_use:
            out.append({"mechanism": mid, "implicit": by_use, "applicable": everywhere,
                        "rows": _changes(kept, _index(S, cat, practices, implicit=False), rerate)})
        if not mine:
            lacking = [e for e in everywhere if e not in by_use]
            if lacking:
                out.append({"mechanism": mid, "applicable": lacking,
                            "rows": _changes(kept, _index(S, cat, practices + [{"id": "what-if", "mechanism": mid}]), rerate)})
            continue
        for p in mine:
            others = [q for q in practices if q is not p]
            covered = [e for e in everywhere if not p.get("scope") or e in p["scope"]]
            entry = {"mechanism": mid, "practice": p["id"], "applicable": everywhere, "scope": p.get("scope", []),
                     "uncovered": [e for e in everywhere if e not in covered and e not in by_use],
                     "rows": _changes(kept, _index(S, cat, others), rerate)}
            if entry["uncovered"]:
                wide = {k: v for k, v in p.items() if k != "scope"}
                entry["extend"] = _changes(kept, _index(S, cat, others + [wide]), rerate)
            if p.get("comment"):
                entry["comment"] = p["comment"]
            out.append(entry)
    return out
