"""Inductive threat analysis: every threat on every matching entity of a setup, its effect on the funds,
and the ratings likelihood, vulnerability, severity and risk. Produces the raw, ID-based analysis data."""
import datetime
import itertools
import json
import sys

import access
import deductive
import loader
import measures
import outcomes as outc
import rating
import feedback as fbk
from feedback import FIELDS
from graph import Setup

TOOL_VERSION = "0.2"


def instances(S, cat):
    """(threat, target ids) for every threat on every entity of its class; plus the list of non-applicable pairs."""
    rows, skipped = [], []
    for tid, t in cat.threats.items():
        cls = t["target"]["class"]
        classes = t["target"].get("subclasses") or [cls]
        ents = [e for c in classes for e in S.ids_of(c)]
        if t["target"].get("cardinality") == "set":
            n = t["target"].get("min_size", 2)
            combos = list(itertools.combinations(ents, n))
        else:
            combos = [(e,) for e in ents]
        for combo in combos:
            e = combo[0]
            if len(combo) == 1 and t.get("applies_when") is not None and not S.holds(e, t["applies_when"]):
                skipped.append({"threat": tid, "entity": e, "reason": "applies_when"})
                continue
            rows.append((t, combo))
    return rows, skipped


def common_cause_peers(S, cat, tid, eid):
    peers = []
    for g in cat.common_cause:
        if tid not in g["threats"] or S.cls(eid) != g["class"]:
            continue
        key = S.group_key(eid, g["group_by"])
        if g["group_by"] and not any(key):
            continue
        peers += [x for x in S.ids_of(g["class"]) if x != eid and S.group_key(x, g["group_by"]) == key]
    return sorted(set(peers))


def unique(outcomes):
    seen, out = set(), []
    for o in outcomes:
        key = (o["wallet"], o["outcome"], o["exploit"])
        if key not in seen:
            seen.add(key)
            out.append(o)
    return out


def exploit_of(cat, outcomes):
    kinds = {o["exploit"] for o in outcomes if o["outcome"] in cat.ratings["outcome_by_asset"]["loss"]}
    for k in cat.ratings["protection"]["exploits"]["order"]:
        if k in kinds:
            return k
    return "none"


def worst_vulnerability(S, cat, tid, insts, combo, st, outcomes, sev, barrier=()):
    """Vulnerability of the worst outcome; with several wallets at the worst severity, the most vulnerable one."""
    table = cat.ratings["outcomes"]
    worst = [o for o in outcomes if sev["value"] > 0 and table[o["outcome"]]["severity"] == sev["value"]]
    best = None
    for w in sorted({o["wallet"] for o in worst}):
        os = [o for o in worst if o["wallet"] == w]
        V = rating.vulnerability(S, cat, tid, insts, rating.footprint(S, combo, st, os), exploit_of(cat, os), w, st, barrier)
        V["wallet"] = w
        if best is None or V["value"] > best["value"]:
            best = V
    return best or rating.vulnerability(S, cat, tid, insts, rating.footprint(S, combo, st, []), "none", None, st, barrier)


def barriers(index):
    return [i for insts in index.values() for i in insts if i.get("barrier_for")]


def rerate(S, cat, item, index):
    """(vulnerability, risk) of a row that was analysed before, with another set of mechanism instances."""
    tid, combo, st, outcomes, sev, L, v_set, s_value = item
    V = worst_vulnerability(S, cat, tid, index.get(tid, []), combo, st, outcomes, sev, barriers(index))
    v = V["value"] if v_set is None else v_set
    return v, rating.risk(cat, L["value"], v, s_value)[1]


def analyze(setup_path, progress=None, check_only=False, what_if=True, given=None, cat=None):
    """`given`: the overrides of the owners (see feedback.py). `cat`: catalogs other than the standard ones."""
    cat = cat or loader.Catalogs()
    data = loader.read_json(setup_path)
    errors = loader.check_catalogs(cat)
    perrors, warnings = loader.preflight(data, cat)
    errors += [f"setup {e}" for e in perrors]
    given = given or fbk.empty()
    errors += [f"feedback {e}" for e in fbk.check(given)]
    if errors:
        return {"errors": errors}
    if check_only:
        return {"errors": [], "warnings": warnings}
    S = Setup(data, cat)
    ev = outc.Evaluator(S)
    for w, t in ev.base_tier.items():
        if t != 0:
            warnings.append(f"baseline: wallet {w} cannot be used even without any threat (tier {t})")
    warnings.extend(ev.baseline)
    mechs = rating.mechanism_instances(S, cat)
    barrier = barriers(mechs)

    pairs, skipped = instances(S, cat)
    answers, scopes = fbk.by_ask(given), fbk.by_scope(given)
    rows, asks, kept = [], {}, []
    for n, (t, combo) in enumerate(pairs):
        tid = t["id"]
        peers = common_cause_peers(S, cat, tid, combo[0]) if len(combo) == 1 else []
        st = access.State()
        for target in list(combo) + peers:
            for impact in t["impacts"]:
                access.apply_impact(S, st, target, impact)
        if t.get("target_acts"):
            st.actors |= set(combo)
        acc = ev.access(st)
        known = access.attacker_secrets(S, st)
        outcomes = unique(ev.evaluate(st, acc, known))
        sev = rating.severity(cat, outcomes)
        L = rating.likelihood(S, cat, t, combo[0], answers) if len(combo) == 1 else rating.likelihood(S, cat, t, "", answers)
        V = worst_vulnerability(S, cat, tid, mechs.get(tid, []), combo, st, outcomes, sev, barrier)
        sev_computed, rid = sev, tid + "@" + "+".join(combo)
        ov = {k: o for k in FIELDS if (o := fbk.pick(scopes, rid, tid, combo, k))}
        L, V, sev = [fbk.override(x, ov[k]) if k in ov else x for k, x in (("L", L), ("V", V), ("S", sev))]
        rl, risk = rating.risk(cat, L["value"], V["value"], sev["value"])
        needs = []
        if L["basis"] == "category_default":
            needs.append("likelihood_default")
        if "asked" in L:
            asks.setdefault(L["asked"], []).append(tid)
        if "ask" in L:
            needs.append("ask:" + L["ask"])
        if any(m.get("note") == "no_response" for m in V["mechanisms"]):
            needs.append("detection_without_response")
        row = {"id": rid, "threat": tid, "entity": list(combo) if len(combo) > 1 else combo[0],
               "class": S.cls(combo[0])}
        if peers:
            row["common_cause"] = peers
        affected = st.summary()
        known = sorted(known)
        if known:
            affected["known"] = known        # all the attacker gets, not only what leaked directly
        if affected:
            row["effects"] = affected
        row["outcomes"] = outcomes
        if any(a["result"] != "ok" for a in acc):
            row["access"] = [a for a in acc if a["result"] != "ok"]
        row.update({"L": L, "V": V, "S": sev, "RL": rl, "R": risk})
        if needs:
            row["needs_input"] = needs
        rows.append(row)
        kept.append((row, (tid, combo, st, outcomes, sev_computed, L, V["value"] if "V" in ov else None, sev["value"])))
        if progress and n % 50 == 0:
            progress(n, len(pairs))
    measure_list = measures.measures(S, cat, kept, lambda item, index: rerate(S, cat, item, index)) if what_if else []
    rows.sort(key=lambda r: (S.cls(r["entity"][0] if isinstance(r["entity"], list) else r["entity"]), str(r["entity"]), r["threat"]))
    cut_sets = deductive.deductive(S, ev, rows) if what_if else []
    sha = loader.sha(setup_path)
    warnings.extend(fbk.stale(given, rows, set(asks), sha))
    return {
        "meta": {
            "tool_version": TOOL_VERSION,
            "generated": datetime.date.today().isoformat(),
            "setup": data["name"],
            "setup_sha": sha,
            "catalogs": cat.hashes(),
            "rows": len(rows),
            "not_applicable": len(skipped),
        },
        "warnings": warnings,
        "asks": [dict({"ask": a, "threats": sorted(set(ts))}, **({"answer": answers[a]} if a in answers else {})) for a, ts in sorted(asks.items())],
        "overrides": given["overrides"],
        "rights": ev.rights_report(),
        "rows": rows,
        "not_applicable": skipped,
        "measures": measure_list,
        "deductive": cut_sets,
    }


# ---------------------------------------------------------------- compact output

def ser(v):
    if isinstance(v, dict):
        return "{}" if not v else "{ " + ", ".join(f"{json.dumps(k)}: {ser(x)}" for k, x in v.items()) + " }"
    if isinstance(v, list):
        return "[" + ", ".join(ser(x) for x in v) + "]"
    return json.dumps(v, ensure_ascii=False)


def write_raw(result, path):
    lines = ["{"]
    for key in ("meta", "warnings", "asks", "overrides", "rights"):
        lines.append(f'  {json.dumps(key)}: {ser(result[key])},')
    lines.append('  "rows": [')
    lines.append(",\n".join("    " + ser(r) for r in result["rows"]))
    lines.append("  ],")
    lines.append('  "not_applicable": [')
    lines.append(",\n".join("    " + ser(r) for r in result["not_applicable"]))
    lines.append("  ],")
    lines.append('  "measures": [')
    lines.append(",\n".join("    " + ser(r) for r in result["measures"]))
    lines.append("  ],")
    lines.append('  "deductive": [')
    lines.append(",\n".join("    " + ser(r) for r in result.get("deductive", [])))
    lines.append("  ]")
    lines.append("}")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
