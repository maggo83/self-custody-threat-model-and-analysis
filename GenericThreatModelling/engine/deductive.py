"""Deductive analysis: from a top event down to the smallest sets of parts that cause it.

For every main wallet and every right (a group of people and the delay they are promised):
- loss cut sets: minimal sets of parts whose loss (destroyed) leaves the group without a way to spend;
- theft path sets: minimal sets of parts whose leak (disclosed) lets an attacker spend.
Both come from the same access tree the inductive analysis uses (access.spend_tree). Each set is then matched with the
threats of the inductive analysis whose effects cover it: a set covered by one threat is a single point of failure."""
from itertools import combinations

import access
from graph import INF
from ontology import is_a


def _loss_events(S, agent):
    """Events that stop an atomic node for the rightful people: the loss of a reached or needed part, or of a person
    whose place it sits in. A part the agent cannot use anyway is already failed and gives no event."""
    def atoms_of(node):
        out = set()
        for a in node["requires"]:
            t = a.get("target")
            if a["type"] in ("reach", "intact") and isinstance(t, str) and agent.atom(a) < INF:
                out.add(t)
                place = S.place(t)
                if place and is_a(S.cls(place), S.model["actor"]["class"]):
                    out.add(place)          # what a person carries or knows is lost with the person
        return out
    return atoms_of


CONTROL = "control:"           # event prefix: the attacker commands the part (its guard does not stop him)


def _theft_events(S):
    """Events that satisfy an atomic node for the attacker: the leak of the part it reaches or of the secret it knows,
    or (a node made by `theft_path_sets`) the control of a guarded part."""
    def atoms_of(node):
        out = []
        for a in node["requires"]:
            t = a.get("target")
            if a["type"] in ("reach", "known") and isinstance(t, str):
                out.append(frozenset([t]))
            elif a["type"] == "control" and isinstance(t, str):
                out.append(frozenset([CONTROL + t]))
        return out
    return atoms_of


def loss_cut_sets(S, wid, people_=None, limit=100):
    """Minimal sets of entities whose loss leaves the people without any way to spend the wallet (relaxed: parts that
    are only unavailable count as present), as sorted lists."""
    agent = access.people(S, access.State(), people_, False)
    node = access.spend_tree(S, wid)
    if access.value(node, agent) == INF:
        return []
    sets = access.failure_sets(_pruned(S, node, agent), _loss_events(S, agent), limit)
    return sorted((sorted(s) for s in sets), key=lambda s: (len(s), s))


def _pruned(S, node, agent):
    """The tree without the branches the agent cannot complete anyway: they add no way and no failure."""
    if node.get("cycle") or node.get("missing"):
        return node
    kids = [c for c in node["children"] if c.get("optional") or access.value(c, agent) < INF or (c.get("guards") and agent.bypasses(c["guards"]))]
    return dict(node, children=[_pruned(S, c, agent) for c in kids])


def theft_path_sets(S, wid, limit=100):
    """Minimal sets of events that let an attacker spend the wallet, as sorted lists: an entity id means its disclosure,
    `control:<id>` that the attacker commands the part (a guarded step, PIN or password, is then no barrier)."""
    node = access.spend_tree(S, wid)

    def with_guards(n):
        if n.get("cycle") or n.get("missing"):
            return n
        kids = []
        for c in n["children"]:
            if c.get("optional"):
                continue
            c = with_guards(c)
            if c.get("guards"):
                leaf = {"action": "@control", "args": {}, "op": "all", "children": [], "requires": [{"type": "control", "target": c["guards"]}]}
                c = {"action": "@guarded", "args": {}, "op": "any", "children": [c, leaf], "requires": []}
            kids.append(c)
        return dict(n, children=kids)
    sets = access.success_sets(with_guards(node), _theft_events(S), lambda n: False, limit)
    # controlling a part includes reaching it
    sets = [frozenset(e for e in s if CONTROL + e not in s) for s in sets if s]
    sets = access._minimal(sets)
    return sorted((sorted(s) for s in sets), key=lambda s: (len(s), s))


def covering_threats(rows, sets, statuses, control=()):
    """For every set, the rows of the inductive analysis whose effects give all its entities one of the statuses
    (a `control:` event needs one of the `control` statuses)."""
    out = []
    for s in sets:
        hits = []
        for r in rows:
            eff = r.get("effects", {})
            got = {e for status in statuses for e in eff.get(status, [])}
            got |= {CONTROL + e for status in control for e in eff.get(status, [])}
            if set(s) <= got:
                hits.append(r["id"])
        out.append({"parts": s, "threats": sorted(hits)})
    return out


def deductive(S, ev, rows):
    """Cut sets and path sets per main wallet, with the single threats that realise them."""
    out = []
    for w in ev.assets:
        if not ev.is_main(w):
            continue
        entry = {"wallet": w, "loss": [], "theft": []}
        groups = sorted({r["people"] for r in ev.rights() if r["wallet"] == w}, key=lambda g: sorted(g))
        for group in groups or [None]:
            sets = loss_cut_sets(S, w, group)
            entry["loss"].append({"people": sorted(group) if group else [], "cut_sets": covering_threats(rows, sets, ("destroyed", "faulty", "tampered"))})
        entry["theft"] = covering_threats(rows, theft_path_sets(S, w), ("disclosed", "controlled", "known"), ("controlled",))
        out.append(entry)
    return out
