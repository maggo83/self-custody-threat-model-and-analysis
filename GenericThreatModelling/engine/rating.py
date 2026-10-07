"""Ratings: likelihood, vulnerability (protection by mechanisms present in the setup), severity, risk."""
from collections import defaultdict
from itertools import combinations, product

import access
from graph import INF, evaluate, flag
from ontology import is_a


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

def effective_schedule(m, practice):
    sched = dict(m.get("schedule", {}))
    if practice and practice.get("interval_months"):
        sched["every_months"] = practice["interval_months"]
    return sched


def quorum_minutes(S, pid):
    """Least time the person needs to bring together what spends a main wallet at once, starting at the best place;
    INF if they cannot alone. The places are those of the parts the person must reach in the access tree."""
    best = INF
    spec, asset = S.model.get("travel", {}), S.model["asset"]
    st = access.State()
    agent = access.People(S, st, [pid], False)
    for w in S.ids_of(asset["class"]):
        if not S.holds(w, asset["main_when"]):
            continue
        for i, pol in enumerate(S.ent(w)[asset["policies"][:-2]]):
            if spec.get("immediate_policies_only", True) and pol.get("delay_blocks", 0):
                continue
            node = access.spend_tree(S, w, i)
            for stops in journeys(S, node, agent):
                best = min(best, S.journey(stops))
    return best


def journeys(S, node, agent, memo=None):
    """Sets of top-level places the agent must visit to complete the node, one per way of doing it (pruned)."""
    memo = {} if memo is None else memo
    if id(node) in memo:
        return memo[id(node)]
    if node.get("cycle") or node.get("missing") or access.value(node, agent) == INF:
        return []
    own = set()
    for a in node["requires"]:
        if a["type"] == "reach" and agent.reach(a["target"]):
            p = S.place(a["target"])
            if p and not S.no_travel(p):
                own.add(S.root(p))
    kids = [journeys(S, c, agent, memo) for c in node["children"] if not c.get("optional") and access.value(c, agent) < INF]
    if node["op"] == "any":
        out = [frozenset(own) | s for k in kids for s in k] or [frozenset(own)]
    else:
        need = len(kids) if node["op"] == "all" else min(node.get("k") or 1, len(kids))
        out = []
        for combo in combinations(kids, need):
            for pick in product(*combo):
                out.append(frozenset(own).union(*pick))
        out = out or [frozenset(own)]
    out = sorted(set(out), key=len)[:50]
    memo[id(node)] = out
    return out


def mechanism_instances(S, cat, implicit=True):
    """Index threat id -> mechanism instances that are present in the setup. A procedural mechanism is present through
    a practice, or, with `implicit`, because the entity is used in a way that does it anyway (implicit_when)."""
    index = defaultdict(list)
    practices = S.data.get("practices", [])
    bands = cat.ratings["protection"].get("travel_minutes", [])
    for m in cat.mechanisms.values():
        if m["form"] == "principle":
            continue
        for eid in S.ids_of(m["target"]):
            fixed = measure = None
            if m["form"] == "structural":
                practice = None
                if m.get("strength_from"):
                    measure = quorum_minutes(S, eid)
                    fixed = max((b["value"] for b in bands if measure >= b["at_least"]), default=0)
                    ok = fixed > 0
                else:
                    ok = S.holds(eid, m.get("present_when"))
            else:
                practice = next((p for p in practices if p["mechanism"] == m["id"] and (not p.get("scope") or eid in p["scope"])), None)
                by_use = implicit and bool(m.get("implicit_when")) and S.holds(eid, m["implicit_when"])
                ok = (practice is not None or by_use) and S.holds(eid, m.get("applies_when"))
            if not ok:
                continue
            sched = effective_schedule(m, practice)
            for a in m["addresses"]:
                index[a["threat"]].append({"mechanism": m["id"], "entity": eid, "effect": a["effect"], "kind": m["kind"],
                                           "schedule": sched, "covers": m.get("covers", "self"), "covers_when": m.get("covers_when"),
                                           "group": m.get("quorum_group", m["id"]), "weaken": m.get("weakened_when", []),
                                           "barrier_for": m.get("barrier_for", []), "strength": fixed, "measure": measure})
    return index


def footprint(S, target_ids, st, outcomes):
    ids = set(target_ids) | {o["wallet"] for o in outcomes if o["outcome"] != "none"}
    for o in outcomes:
        ids |= access.deps(S, o["wallet"])
    for e in list(ids):
        if e in S.by_id:
            ids.update(p for p in (S.place(e), *S.chain(e)) if p)
    return ids


def related(S, inst, fp):
    if inst.get("covers_when") is not None:
        return S.holds(inst["entity"], inst["covers_when"], {"$footprint": sorted(fp)})
    if inst["covers"] == "own":
        return inst["entity"] in fp
    c = S.cls(inst["entity"])
    if flag(c, "singleton") or is_a(c, S.model["actor"]["class"]):
        return True
    return inst["entity"] in fp


def quorum_covered(S, wid, devices):
    """Every group of signers that can spend under one policy has a member whose devices all are in `devices`."""
    q, asset = S.model["asset"]["quorum"], S.model["asset"]
    for p in S.ent(wid)[asset["policies"][:-2]]:
        uncovered = 0
        for sg in p["signers"]:
            ds = set(S.values(sg, q["signer_devices"]))
            uncovered += not ds or not ds <= set(devices)
        if uncovered >= S.values(p, q["threshold"])[0]:
            return False
    return True


def vulnerability(S, cat, tid, insts, fp, exploit, wallet=None, st=None, barrier=()):
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
            if not quorum_covered(S, wallet, having):
                rec["note"] = "quorum_gap"
                continue
        if inst["effect"] in ("eliminates", "reduces"):
            strength = inst["strength"] if inst.get("strength") is not None else prot["prevention"][inst["effect"]]
            if inst.get("measure") is not None:
                rec["minutes"] = None if inst["measure"] == INF else inst["measure"]
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
                if strength and S.holds(inst["entity"], rule["when"], {"@state": st or access.State()}):
                    strength = max(0, strength + rule["delta"])
                    rec["weakened"] = rule["reason"]
                    break
            detection = max(detection, strength)
        if strength > rec["strength"]:
            rec["strength"] = strength
            rec.pop("note", None)
    if wallet:
        for inst in barrier:
            if inst["entity"] != wallet or exploit not in inst.get("barrier_for", []) or inst["effect"] not in ("eliminates", "reduces"):
                continue
            strength = prot[exploit][inst["effect"]]
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
