"""Per-person manuals: what one person must know and do, generated from the setup, the access trees and the analysis.

Nothing in a manual is written by hand for a setup: the steps are the actions of the catalog (RecoveryActions.json),
pruned to what the person's group can actually do; the maintenance tasks are the practices that touch what the person
reaches; the incidents are the threats of the analysis on those parts, with the detection signals and the responses of
the catalogs. Only entities the person can reach or know are named (see `scope`)."""
import html
from pathlib import Path

import access
import loader
import outcomes
import rating
from graph import INF, Setup


def scope(S, ev, pid):
    """The entity ids a person may know about: what they reach and carry, what those hold, the wallets they have a
    right to (with the parts their group can use) and the people of those rights."""
    ids = set(S.reachable_entities(pid)) | {p for p in S.reach(pid)} | {pid}
    for e in list(ids):
        ids |= {v for v in S.values(e, "holds") if isinstance(v, str) and v in S.by_id}
    for r in ev.rights():
        if pid in r["people"]:
            ids.add(r["wallet"])
            ids |= set(r["people"])
            agent = access.people(S, access.State(), r["people"], False)
            ids |= usable(S, access.spend_tree(S, r["wallet"]), agent)
    return ids


def usable(S, node, agent, out=None):
    """Entities of the branches of a tree the agent can complete."""
    out = set() if out is None else out
    if access.value(node, agent) == INF:
        return out
    for a in node["requires"]:
        if isinstance(a.get("target"), str) and a["target"] in S.by_id:
            out.add(a["target"])
    for c in node["children"]:
        if c.get("optional") or access.value(c, agent) < INF:
            usable(S, c, agent, out)
    return out


class Manual:
    def __init__(self, S, ev, cat, texts, result, pid):
        self.S, self.ev, self.cat, self.t, self.result, self.pid = S, ev, cat, texts, result, pid
        self.m = texts["manual"]
        self.ids = scope(S, ev, pid)

    # ------------------------------------------------------------------ helpers
    def name(self, eid):
        return self.S.name(eid) if eid in self.S.by_id else str(eid)

    def where(self, eid):
        """'(at Home, in Bag 1)' for a thing, '' for information."""
        chain = [c for c in self.S.chain(eid) if c in self.S.by_id]
        return (" (" + ", ".join(self.name(c) for c in chain) + ")") if chain else ""

    def blocks(self, n):
        return self.m["blocks"].format(blocks=n, days=max(1, round(n / 144)))

    def fmt(self, key, **kw):
        return self.m[key].format(**{k: html.escape(str(v)) for k, v in kw.items()})

    # ------------------------------------------------------------------ the access tree as a checklist
    def steps(self, node, agent, depth=0, seen=frozenset()):
        """Nested list items for a tree, pruned to what the agent can do; attacker-only steps are left out.
        Alternatives come cheapest first; arguments already named by the parent are not repeated."""
        a = self.cat.actions[node["action"]]
        if a.get("for") == "attacker" or node.get("cycle") or node.get("missing"):
            return ""
        kids = [c for c in node["children"] if c.get("optional") or access.value(c, agent) < INF]
        if node["op"] in ("k", "any"):
            kids = sorted(kids, key=lambda c: access.value(c, agent))
        mine = {v for v in node["args"].values() if isinstance(v, str) and v in self.S.by_id}
        inner = "".join(self.steps(c, agent, depth + 1, seen | mine) for c in kids)
        args = [self.name(v) + self.where(v) for v in node["args"].values() if isinstance(v, str) and v in self.S.by_id and v not in seen]
        label = html.escape(a["name"]) + (": <b>" + html.escape(", ".join(args)) + "</b>" if args else "")
        notes = []
        for r in node["requires"]:
            if r["type"] == "wait" and r.get("blocks"):
                notes.append(self.blocks(r["blocks"]))
            if r["type"] == "have" and r.get("what"):
                notes.append(self.m["tools"].get(r["what"], r["what"]))
        if node.get("optional"):
            notes.append(self.m["optional"])
        how = ""
        if a["type"] == "composite" and kids:
            k = node.get("k")
            how = self.m["combinator"][node["op"]].format(k=k, n=len(kids))
        text = f"{label}" + (f" <small>({html.escape('; '.join(notes))})</small>" if notes else "")
        desc = f"<div class='desc'>{html.escape(a['description'])}</div>" if depth <= 1 or not kids else ""
        return f"<li>{text}{desc}" + (f"<div class='how'>{html.escape(how)}</div><ul>{inner}</ul>" if inner else "") + "</li>"

    def checklist(self, action_id, args, agent):
        node = access.tree(self.S, action_id, args)
        if access.value(node, agent) == INF:
            return f"<p class='warn'>{html.escape(self.m['impossible'])}</p>"
        return f"<ul class='steps'>{self.steps(node, agent)}</ul>"

    def action_list(self, action_ids, args):
        """Steps of catalog actions without pruning (procedures, responses)."""
        out = []
        for aid in action_ids:
            a = self.cat.actions.get(aid)
            if not a:
                continue
            node = access.tree(self.S, aid, {p["name"]: args.get(p["name"]) for p in a.get("params", [])} if a.get("params") else {})
            out.append(f"<li><b>{html.escape(a['name'])}</b><div class='desc'>{html.escape(a['description'])}</div>{self.plain(node)}</li>")
        return f"<ul class='steps'>{''.join(out)}</ul>" if out else ""

    def plain(self, node, depth=0):
        a = self.cat.actions[node["action"]]
        if a.get("for") == "attacker" or depth > 3:
            return ""
        kids = [c for c in node["children"] if not c.get("cycle") and not c.get("missing")]
        if not kids:
            return ""
        items = []
        for c in kids:
            ca = self.cat.actions[c["action"]]
            if ca.get("for") == "attacker":
                continue
            args = [self.name(v) + self.where(v) for v in c["args"].values() if isinstance(v, str) and v in self.S.by_id and v in self.ids]
            items.append(f"<li>{html.escape(ca['name'])}" + (": <b>" + html.escape(", ".join(args)) + "</b>" if args else "") + self.plain(c, depth + 1) + "</li>")
        how = self.m["combinator"][node["op"]].format(k=node.get("k"), n=len(items))
        return f"<div class='how'>{html.escape(how)}</div><ul>{''.join(items)}</ul>" if items else ""

    # ------------------------------------------------------------------ sections
    def overview(self):
        S, p = self.S, self.S.ent(self.pid)
        roles = ", ".join(p.get("roles", [])) or self.m["no_role"]
        lines = [f"<p>{self.fmt('intro', name=p['name'], roles=roles)}</p>"]
        rights = [r for r in self.ev.rights() if self.pid in r["people"]]
        if rights:
            items = []
            for r in rights:
                others = [self.name(q) for q in sorted(r["people"]) if q != self.pid]
                who = self.fmt("with", others=", ".join(others)) if others else self.m["alone"]
                when = self.m["at_once"] if r["after"] == 0 else self.fmt("after", blocks=self.blocks(r["after"]))
                items.append(f"<li>{self.fmt('right', wallet=self.name(r['wallet']), who=who, when=when)}</li>")
            lines.append(f"<h3>{html.escape(self.m['h_rights'])}</h3><ul>{''.join(items)}</ul>")
        else:
            lines.append(f"<p>{html.escape(self.m['no_rights'])}</p>")
        # what the person reaches, by place
        by_place = {}
        for e in sorted(S.reachable_entities(self.pid), key=lambda e: (S.place(e) or "", e)):
            by_place.setdefault(S.place(e), []).append(e)
        if by_place:
            parts = []
            for place, items in by_place.items():
                names = ", ".join(self.name(e) + (self.where(e) if S.container(e) != place else "") for e in items)
                parts.append(f"<li><b>{html.escape(self.name(place))}</b>: {html.escape(names)}</li>")
            lines.append(f"<h3>{html.escape(self.m['h_reach'])}</h3><ul>{''.join(parts)}</ul>")
        memory = [e for e in S.reachable_entities(self.pid) if S.place(e) == self.pid]
        if memory:
            lines.append(f"<p>{self.fmt('carried', items=', '.join(self.name(e) for e in memory))}</p>")
        return "".join(lines)

    def tasks(self):
        S, out = self.S, []
        groups = {}
        for r in self.ev.rights():
            if self.pid in r["people"]:
                groups.setdefault(r["wallet"], []).append(r)
        for wid, rights in groups.items():
            out.append(f"<h3>{self.fmt('h_spend', wallet=self.name(wid))}</h3>")
            for r in sorted(rights, key=lambda r: (r["after"], sorted(r["people"]))):
                others = [self.name(q) for q in sorted(r["people"]) if q != self.pid]
                who = self.fmt("with", others=", ".join(others)) if others else self.m["alone"]
                when = self.m["at_once"] if r["after"] == 0 else self.fmt("after", blocks=self.blocks(r["after"]))
                agent = access.people(S, access.State(), r["people"], False)
                out.append(f"<h4>{html.escape(who)}, {html.escape(when)}</h4>")
                out.append(self.checklist(self.S.model["goals"]["spend"]["action"], {"wallet": wid}, agent))
            out.append(f"<h4>{html.escape(self.m['h_send'])}</h4>" + self.action_list(self.m["send_actions"], {"wallet": wid}))
            out.append(f"<h4>{html.escape(self.m['h_receive'])}</h4>" + self.action_list(self.m["receive_actions"], {"wallet": wid}))
        return "".join(out) if out else f"<p>{html.escape(self.m['no_rights'])}</p>"

    def setup_section(self):
        """Owners: creating the setup. Others: taking over when the owners are gone (their delayed rights)."""
        S = self.S
        owner = self.ev.is_owner(self.pid)
        if owner:
            return f"<p>{html.escape(self.m['setup_owner'])}</p>" + self.action_list(self.m["setup_actions"], {})
        delayed = [r for r in self.ev.rights() if self.pid in r["people"] and r["after"] > 0]
        if not delayed:
            return f"<p>{html.escape(self.m['setup_none'])}</p>"
        out = [f"<p>{html.escape(self.m['setup_heir'])}</p>"]
        for r in delayed:
            gone = access.State()
            for q in S.ids_of(S.model["actor"]["class"]):
                if q not in r["people"] and self.ev.is_owner(q):
                    gone.add(q, "destroyed")
            agent = access.people(S, gone, r["people"], False)
            others = [self.name(q) for q in sorted(r["people"]) if q != self.pid]
            who = self.fmt("with", others=", ".join(others)) if others else self.m["alone"]
            out.append(f"<h4>{self.fmt('takeover', wallet=self.name(r['wallet']), who=who, when=self.blocks(r['after']))}</h4>")
            out.append(self.checklist(S.model["goals"]["spend"]["action"], {"wallet": r["wallet"]}, agent))
        return "".join(out)

    def maintenance(self):
        S, cat, out = self.S, self.cat, []
        practices = S.data.get("practices", [])
        for p in practices:
            m = cat.mechanisms.get(p["mechanism"])
            if not m:
                continue
            targets = [e for e in S.ids_of(m["target"]) if (not p.get("scope") or e in p["scope"]) and e in self.ids and S.holds(e, m.get("applies_when"))]
            if not targets:
                continue
            sched = rating.effective_schedule(m, p)
            when = schedule_text(self.t, sched)
            out.append(f"<h3>{html.escape(m['name'])} <small>{html.escape(when)}</small></h3><p>{html.escape(m['description'])}</p>"
                       f"<p>{self.fmt('applies_to', items=', '.join(self.name(e) + self.where(e) for e in targets))}</p>"
                       + self.action_list(m.get("procedure", []), {}) + (f"<p class='signal'>{self.fmt('signal', text=m['signal'])}</p>" if m.get("signal") else ""))
        return "".join(out) if out else f"<p>{html.escape(self.m['no_maintenance'])}</p>"

    def incidents(self):
        """Threats of the analysis on what the person reaches or on their wallets: signal, and what to do."""
        cat, out = self.cat, []
        mine = {w for r in self.ev.rights() if self.pid in r["people"] for w in [r["wallet"]]}
        by_threat = {}
        for row in self.result["rows"]:
            ents = row["entity"] if isinstance(row["entity"], list) else [row["entity"]]
            hits_mine = any(o["wallet"] in mine for o in row["outcomes"])
            if row["S"]["value"] == 0 or not (set(ents) & self.ids or hits_mine):
                continue
            by_threat.setdefault(row["threat"], []).append((row, [e for e in ents if e in self.ids]))
        detections = {}
        for m in cat.mechanisms.values():
            for a in m.get("addresses", []):
                if a["effect"] == "detects" and m.get("signal"):
                    detections.setdefault(a["threat"], []).append(m["signal"])
        responses = {}
        for a in cat.actions.values():
            for tid in a.get("responds_to", []):
                responses.setdefault(tid, []).append(a["id"])
        for tid, rows in sorted(by_threat.items(), key=lambda kv: -max(r["R"] for r, _ in kv[1])):
            t = cat.threats[tid]
            ents = sorted({e for _, es in rows for e in es})
            risk = max(r["R"] for r, _ in rows)
            out.append(f"<h3>{html.escape(t['name'])} <span class='chip r{risk}'>{risk}</span></h3><p>{html.escape(t['description'])}</p>")
            if ents:
                out.append(f"<p>{self.fmt('concerns', items=', '.join(self.name(e) + self.where(e) for e in ents))}</p>")
            if tid in detections:
                out.append(f"<p class='signal'>{self.fmt('signal', text=' '.join(sorted(set(detections[tid]))))}</p>")
            if tid in responses:
                out.append(f"<p>{html.escape(self.m['respond'])}</p>" + self.action_list(sorted(set(responses[tid])), {}))
        return "".join(out) if out else f"<p>{html.escape(self.m['no_incidents'])}</p>"

    def findings(self):
        notes = [w for w in self.result["warnings"] if w.startswith("rights:") and self.name(self.pid) in w]
        return "<ul>" + "".join(f"<li>{html.escape(n[8:])}</li>" for n in notes) + "</ul>" if notes else ""

    def html(self):
        m = self.m
        sections = [
            (m["h_overview"], self.overview()),
            (m["h_setup"], self.setup_section()),
            (m["h_tasks"], self.tasks()),
            (m["h_maintenance"], self.maintenance()),
            (m["h_incidents"], self.incidents()),
        ]
        findings = self.findings()
        if findings:
            sections.append((m["h_findings"], findings))
        toc = "".join(f"<li><a href='#m{i}'>{html.escape(h)}</a></li>" for i, (h, _) in enumerate(sections))
        body = "".join(f"<section id='m{i}'><h2>{html.escape(h)}</h2>{b}</section>" for i, (h, b) in enumerate(sections))
        return f"<h1>{self.fmt('title', name=self.name(self.pid), setup=self.S.data['name'])}</h1><p class='note'>{html.escape(m['disclaimer'])}</p><ol class='toc'>{toc}</ol>{body}"


STYLE = """body{font:15px/1.45 system-ui,sans-serif;max-width:52em;margin:2em auto;padding:0 1em;color:#222}
h1{font-size:1.5em}h2{border-bottom:1px solid #ccc;margin-top:2em}h3{margin-bottom:.2em}h4{margin:1em 0 .2em}small{color:#666;font-weight:normal}
ul.steps{padding-left:1.2em}ul.steps li{margin:.4em 0}.desc{color:#555;font-size:.92em}.how{color:#666;font-style:italic;font-size:.9em;margin-top:.2em}
.note,.signal{background:#f4f4f0;padding:.5em .8em;border-left:3px solid #999}.warn{color:#a00}.chip{display:inline-block;min-width:1.4em;text-align:center;border-radius:.7em;color:#fff;font-size:.8em;padding:0 .4em;vertical-align:middle}
.r0{background:#6a6}.r1{background:#9b4}.r2{background:#db3}.r3{background:#e73}.r4{background:#c33}
ol.toc{columns:2}@media print{ol.toc{display:none}}"""


def render(S, ev, cat, result, pid):
    texts = loader.read_json(cat.data_dir / "Texts.json")
    body = Manual(S, ev, cat, texts, result, pid).html()
    title = html.escape(texts["manual"]["title"].format(name=S.name(pid), setup=S.data["name"]))
    return f"<!DOCTYPE html><html><head><meta charset='utf-8'><title>{title}</title><style>{STYLE}</style></head><body>{body}</body></html>"


def write_all(result, setup_path, out_dir, cat=None):
    """One HTML file per person; returns the paths written."""
    cat = cat or loader.Catalogs()
    S = Setup(loader.read_json(setup_path), cat)
    ev = outcomes.Evaluator(S)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = []
    for pid in S.ids_of(S.model["actor"]["class"]):
        p = out_dir / f"{Path(setup_path).stem}.manual.{pid}.html"
        p.write_text(render(S, ev, cat, result, pid), encoding="utf-8")
        paths.append(p)
    return paths


def schedule_text(texts, sched):
    t, parts = texts["schedule"], []
    for key in ("every_months", "every_fraction_of_delay"):
        if key in sched:
            parts.append(t[key].format(n=sched[key]))
    if "trigger" in sched:
        parts.append(t["trigger"][sched["trigger"]])
    return ", ".join(parts)
