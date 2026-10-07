"""Ratings: likelihood, vulnerability (protection by mechanisms present in the setup), severity, risk."""
from collections import defaultdict

import ontology
import predicates


def clamp(v, lo=0, hi=4):
    return max(lo, min(hi, v))


# ---------------------------------------------------------------- likelihood

def likelihood(S, cat, threat, eid, answers=None):
    """`answers`: {question: override} of the owners; it replaces the catalog value as the base of the threats the question concerns."""
    tid = threat["id"]
    entry = threat.get("likelihood")
    if entry is None:
        base, basis, ask = cat.category_likelihood[threat["category"]], "category_default", None
    else:
        base, basis, ask = (entry, "threat", None) if isinstance(entry, int) else (entry["value"], "threat", entry.get("ask"))
    catalog_base = base
    answer = (answers or {}).get(ask) if ask else None
    if answer:
        base, basis = answer["value"], "answered"
    applied = []
    if eid in S.by_id:
        for i, m in enumerate(threat.get("likelihood_modifiers", [])):
            if S.holds(eid, m["when"]):
                applied.append((i, m["delta"]))
    out = {"value": clamp(base + sum(d for _, d in applied)), "base": base, "basis": basis}
    if applied:
        out["modifiers"] = [i for i, _ in applied]
    if ask:
        out["asked"] = ask
        if answer:
            out["catalog_base"] = catalog_base
            out["answer"] = {k: answer[k] for k in ("reason", "by", "date") if k in answer}
        else:
            out["ask"] = ask
    return out


# ---------------------------------------------------------------- mechanisms present in the setup

def target_entities(S, target):
    return S.ids_of(target)


def effective_schedule(m, practice):
    sched = dict(m.get("schedule", {}))
    if practice and practice.get("interval_months"):
        sched["every_months"] = practice["interval_months"]
    return sched


def mechanism_instances(S, cat, implicit=True):
    """Index threat id -> mechanism instances that are present in the setup. A procedural mechanism is present through
    a practice, or, with `implicit`, because the entity is used in a way that does it anyway (implicit_when)."""
    index = defaultdict(list)
    practices = S.data.get("practices", [])
    for m in cat.mechanisms.values():
        if m["form"] == "principle":
            continue
        for eid in target_entities(S, m["target"]):
            pred = m.get("predicate")
            if m["form"] == "structural":
                ok = S.holds(eid, m.get("present_when")) and (not pred or predicates.holds(S, pred, eid))
                practice = None
            else:
                practice = next((p for p in practices if p["mechanism"] == m["id"] and (not p.get("scope") or eid in p["scope"])), None)
                by_use = implicit and bool(m.get("implicit_when")) and S.holds(eid, m["implicit_when"])
                ok = (practice is not None or by_use) and S.holds(eid, m.get("applies_when")) and (not pred or predicates.holds(S, pred, eid))
            if not ok:
                continue
            fixed = measure = None
            if m.get("strength_from"):
                measure = S.quorum_minutes(eid)
                fixed = max((b["value"] for b in cat.ratings["protection"]["travel_minutes"] if measure >= b["at_least"]), default=0)
            sched = effective_schedule(m, practice)
            for a in m["addresses"]:
                index[a["threat"]].append({"mechanism": m["id"], "entity": eid, "effect": a["effect"], "kind": m["kind"],
                                           "schedule": sched, "covers": m.get("covers", "self"),
                                           "group": m.get("quorum_group", m["id"]), "weaken": m.get("weakened_when", []),
                                           "strength": fixed, "measure": measure})
    return index


def footprint(S, target_ids, st, outcomes):
    ids = set(target_ids) | {o["wallet"] for o in outcomes if o["outcome"] != "none"}
    for o in outcomes:
        ids |= S.deps(o["wallet"])
    for e in list(ids):
        if e in S.by_id and S.loc_of(e):
            loc = S.loc_of(e)
            while loc:
                ids.add(loc)
                loc = S.ent(loc).get("part_of")
    return ids


def related(S, inst, fp):
    if inst["covers"] == "own":
        return inst["entity"] in fp
    c = S.cls(inst["entity"])
    if c in ("Plan", "Person"):
        return True
    if inst["covers"] == "colocated_secrets":
        mine = set()
        for sid in S.deps(inst["entity"]):
            if S.cls(sid) in ontology.CREDENTIALS:
                mine |= {S.root(l) for l in S.secret_locations(sid)}
        theirs = {S.root(e) for e in fp if e in S.by_id and S.cls(e) == "Location"}
        return bool(mine & theirs)
    return inst["entity"] in fp


def vulnerability(S, cat, tid, insts, fp, exploit, wallet=None, known=(), barrier=()):
    prot = cat.ratings["protection"]
    det = prot["detection"]
    fast = det["fast_enough"].get(exploit, "any")
    grouped, prevention, detection = {}, 0, 0
    for inst in insts:
        if not related(S, inst, fp):
            continue
        key = (inst["mechanism"], inst["effect"])
        rec = grouped.setdefault(key, {"mechanism": inst["mechanism"], "effect": inst["effect"], "entities": [], "strength": 0})
        rec["entities"].append(inst["entity"])
        if inst["covers"] == "quorum" and wallet:
            having = {i["entity"] for i in insts if i["group"] == inst["group"]}
            if not S.quorum_covered(wallet, having):
                rec["note"] = "quorum_gap"
                continue
        if inst["effect"] in ("eliminates", "reduces"):
            strength = inst["strength"] if inst.get("strength") is not None else prot["prevention"][inst["effect"]]
            if inst.get("measure") is not None:
                rec["minutes"] = None if inst["measure"] == float("inf") else inst["measure"]
            prevention = max(prevention, strength)
        else:
            sched, strengths = inst["schedule"], []
            if "trigger" in sched and (fast == "any" or sched["trigger"] in fast):
                strengths.append(det["by_trigger"].get(sched["trigger"], 0))
            if "every_months" in sched and fast == "any":
                strengths.append(next((b["value"] for b in det["by_interval_months"] if sched["every_months"] <= b["max"]), 0))
            if sched.get("trigger") == "at_setup" and set(cat.threats[tid]["phases"]) <= set(det["setup_check"]["phases"]):
                strengths.append(det["setup_check"]["value"])
            strength = max(strengths, default=0)
            self_responding = sched.get("trigger") in det["self_responding_triggers"]
            if det["requires_response"] and not self_responding and not cat.has_response(tid):
                strength, rec["note"] = 0, "no_response"
            elif strength == 0:
                rec.setdefault("note", "too_slow")
            for rule in inst["weaken"]:
                if strength and predicates.KNOWLEDGE[rule["known"]](S, inst["entity"], known):
                    strength = max(0, strength + rule["delta"])
                    rec["weakened"] = rule["reason"]
                    break
            detection = max(detection, strength)
        if strength > rec["strength"]:
            rec["strength"] = strength
            rec.pop("note", None)
    if exploit == "after_delay" and wallet:
        for inst in barrier:
            if inst["entity"] != wallet or inst["effect"] not in ("eliminates", "reduces"):
                continue
            strength = prot["after_delay"][inst["effect"]]
            rec = grouped.setdefault((inst["mechanism"], inst["effect"]), {"mechanism": inst["mechanism"], "effect": inst["effect"], "entities": [], "strength": 0})
            rec["entities"].append(wallet)
            rec["strength"], rec["barrier"] = max(rec["strength"], strength), True
            prevention = max(prevention, strength)
    p = max(prevention, detection)
    if prevention >= 1 and detection >= 1:
        p += prot["bonus_prevention_and_detection"]
    p = min(p, prot["max"])
    for rec in grouped.values():
        rec["entities"] = sorted(set(rec["entities"]))
    return {"value": 4 - p, "prevention": prevention, "detection": detection, "mechanisms": sorted(grouped.values(), key=lambda r: (r["mechanism"], r["effect"]))}


# ---------------------------------------------------------------- severity and risk

def severity(cat, outcomes):
    table = cat.ratings["outcomes"]
    worst = max(outcomes, key=lambda o: table[o["outcome"]]["severity"], default=None)
    if worst is None:
        return {"value": 0, "outcome": "none"}
    return {"value": table[worst["outcome"]]["severity"], "outcome": worst["outcome"]}


def risk(cat, L, V, S_):
    rl = clamp(L + V - 4, cat.ratings["residual_likelihood"]["min"], cat.ratings["residual_likelihood"]["max"])
    return rl, cat.ratings["risk_matrix"]["values"][rl][S_]
