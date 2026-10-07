"""HTML report of an analysis: classic table and the setup diagram coloured by risk, in one offline file.
The texts come from Texts.json; the page draws the diagram itself from the structure data."""
import base64
import json
from pathlib import Path

import access
import loader
import outcomes
import rating
from graph import Setup
import ontology
from ontology import is_a

ENGINE = Path(__file__).resolve().parent
TEMPLATE = ENGINE / "report.template.html"
IMAGES = loader.LOOKUPS / "DeviceImages" / "thumb"
CLASS_ORDER = ontology.CONCRETE


def holds(S, eid):
    """What one finds by opening a backup or holding a device: the `holds` derived attribute of its class."""
    return {v for v in S.values(eid, "holds") if isinstance(v, str) and v in S.by_id}


def device_images(S):
    """{model key: data URI} for the signing devices of the setup that have a picture, and {device id: model key}."""
    table = loader.csv_rows(loader.LOOKUPS / "DeviceImages.csv", ("vendor", "model"))
    pictures, of = {}, {}
    for d in S.of("SigningDevice"):
        row = table.get((d["vendor"], d["model"]))
        path = IMAGES / f"{row['file']}.webp" if row else None
        if path and path.exists():
            pictures.setdefault(row["file"], "data:image/webp;base64," + base64.b64encode(path.read_bytes()).decode())
            of[d["id"]] = {"file": row["file"], "match": row["match"]}
    return pictures, of


def spendable(S, ev, pid):
    """The wallets and spending policies (`wallet#n`) that the person can satisfy alone, or together with the others of a right to that wallet, whatever the delay."""
    out = set()
    tries = [(None, {pid})] + [(r["wallet"], set(r["people"])) for r in ev.rights() if pid in r["people"]]
    policies = S.model["asset"]["policies"][:-2]
    for only, group in tries:
        agent = access.People(S, access.State(), group, True)
        for wal in S.of("Wallet"):
            if only and wal["id"] != only:
                continue
            for i in range(len(wal[policies])):
                if access.value(access.spend_tree(S, wal["id"], i), agent) < access.INF:
                    out |= {wal["id"], f"{wal['id']}#{i + 1}"}
    return out


def implicit_id(wid):
    return f"implicit:{wid}"


def coordinator_holds(S, w, cid):
    """The descriptors a coordinator has: kept explicitly, or derived on its host from the seeds that are there (implicit)."""
    kept, out = S.ent(cid).get("stores_descriptors", []), []
    for wid in S.values(cid, "holds"):
        did = S.values(wid, "descriptor")
        did = did[0] if did else None
        if did in kept:
            out.append({"id": did, "name": w.name(did), "c": "Descriptor", "tip": f"descriptor {w.name(did)} is kept by this coordinator"})
        else:
            out.append({"id": did or implicit_id(wid), "name": w.name(did) if did else f"Descriptor of {w.name(wid)}", "c": "Descriptor", "implicit": True,
                        "tip": f"the descriptor of {w.name(wid)} is derived on this host from the seeds that are there"})
    return out


def structure(S, ev, w, texts, images=False):
    """The setup as plain data for the diagram: cards, links, and what each person can reach."""
    subtitles = texts.get("subtitle", {})
    nodes = []
    pictures, of = device_images(S) if images else ({}, {})
    for eid, (c, e) in S.by_id.items():
        node = {"id": eid, "c": c, "name": w.name(eid), "sub": loader.message(S, eid, subtitles[c]).replace("?", "").strip(" ,") if c in subtitles else ""}
        if eid in of:
            node["img"], node["imgmatch"] = of[eid]["file"], of[eid]["match"]
        if is_a(c, "Device"):
            node["holds"] = [{"id": s, "name": w.name(s), "c": S.cls(s),
                              "tip": f"{texts['classes'][S.cls(s)][0].lower()} {w.name(s)} is on this device"}
                             for s in S.values(eid, "holds")]
        if c == "Coordinator":
            node["holds"] = coordinator_holds(S, w, eid)
        if is_a(c, S.model["actor"]["class"]):
            node["may"] = w.rights_of(eid)
        if c == "Backup":
            node["subjects"] = sorted({k for item in e["items"] for k in item["subject"]})
        container = S.container(eid)
        if container:
            node["in"] = container
        if c == "Wallet":
            node["custom"] = e["definition"] == "custom"
            node["tripwire"] = not ev.is_main(eid)
            node["policies"] = [f"{p['threshold']} of {len(p['signers'])}, " + (f"after {p['delay_blocks']} blocks" if p["delay_blocks"] else "at once")
                                for p in e["spending_policies"]]
        nodes.append(node)
    nodes += [{"id": implicit_id(wal["id"]), "c": "Descriptor", "name": f"Descriptor of {w.name(wal['id'])}", "sub": "derived from the keys", "implicit": True}
              for wal in S.of("Wallet") if not S.values(wal["id"], "descriptor")]
    nodes.sort(key=lambda n: n["c"] == "Wallet" and n["tripwire"])
    edges = []
    for loc in S.of("Location"):
        edges += [[p, loc["id"], "access"] for p in loc.get("access", [])]
    for wal in S.of("Wallet"):
        for i, p in enumerate(wal["spending_policies"], 1):
            for sg in p["signers"]:
                edges.append([f"{wal['id']}#{i}", sg["seed"], "signer"])
                if "passphrase" in sg:
                    edges.append([f"{wal['id']}#{i}", sg["passphrase"], "passphrase"])
        d = S.values(wal["id"], "descriptor")
        edges.append([wal["id"], d[0] if d else implicit_id(wal["id"]), "descriptor"])
        edges.append(["@plan", wal["id"], "plan"])
    for seed in S.of("Seed"):
        edges += [[seed["id"], d, "loaded"] for d in seed.get("devices", [])]
    for dev in S.of("Device"):
        edges += [[dev["id"], x, "stores"] for x in dev.get("stores_descriptors", [])]
        if "pin" in dev:
            edges.append([dev["id"], dev["pin"], "pin"])
    for c in S.of("Coordinator"):
        edges += [[c["id"], h["id"], "stores"] for h in coordinator_holds(S, w, c["id"])]
        if "password" in c:
            edges.append([c["id"], c["password"], "pin"])
    for bag in S.of("TamperEvidentBag"):
        edges.append([bag["id"], bag["strip"], "strip"])
    for b in S.of("Backup"):
        for item in b["items"]:
            for k, v in item["subject"].items():
                edges.append([b["id"], "@plan" if k == "plan" else v, "content"])
            for alt in item.get("encrypted_with", []):
                edges += [[b["id"], v, "encrypted"] for v in alt.values()]
    acc, spend = {}, {}
    for p in S.ids_of(S.model["actor"]["class"]):
        items = set(S.reachable_entities(p))
        got = set().union(*[holds(S, e) for e in items]) if items else set()
        spend[p] = spendable(S, ev, p)
        acc[p] = sorted({p} | {x for x in S.reach(p) if x in S.by_id} | items | got | spend[p])
    who, deps = {}, {}
    for wid in S.ids_of("Wallet"):
        who[wid] = sorted({p for p in S.ids_of(S.model["actor"]["class"]) if wid in spend[p]} | {p for r in ev.rights() if r["wallet"] == wid for p in r["people"]})
        deps[wid] = sorted(access.deps(S, wid))
        if len(S.ent(wid)["spending_policies"]) > 1:
            for i in range(len(S.ent(wid)["spending_policies"])):
                who[f"{wid}#{i + 1}"] = sorted(p for p in S.ids_of(S.model["actor"]["class"]) if f"{wid}#{i + 1}" in spend[p])
                deps[f"{wid}#{i + 1}"] = sorted(access.deps(S, wid, i))
    return {"nodes": nodes, "edges": edges, "access": acc, "who": who, "images": pictures, "deps": deps}


def context(S, chain, wallets):
    """Secrets and spending policies that link the affected entities to the wallets: the policies whose access trees
    touch the chain, and the secrets whose own access trees do."""
    nodes, policies = set(), []
    for wid in wallets:
        if wid not in S.by_id or S.cls(wid) != "Wallet":
            continue
        for i in range(len(S.ent(wid)["spending_policies"])):
            ents = access.entities(S, access.spend_tree(S, wid, i)) - {wid}
            if ents & chain:
                policies.append(f"{wid}#{i + 1}")
                for s in ents:
                    if is_a(S.cls(s), "Secret") and (s in chain or access.entities(S, access.goal(S, "know", secret=s)) & chain):
                        nodes.add(s)
    return sorted(nodes - chain), policies


class Writer:
    def __init__(self, S, ev, cat, texts):
        self.S, self.ev, self.cat, self.t = S, ev, cat, texts
        self.ratings = cat.ratings

    def name(self, eid):
        if eid not in self.S.by_id:
            return eid
        e = self.S.ent(eid)
        return e.get("name") or (f"strip {e['serial']}" if "serial" in e else eid)

    def names(self, ids, limit=4):
        ids = list(ids)
        text = ", ".join(self.name(i) for i in ids[:limit])
        return text + (f" and {len(ids) - limit} more" if len(ids) > limit else "")

    def band(self, scale, value):
        return self.ratings["scales"][scale]["bands"][value]["probability"]

    def rights_of(self, pid):
        """The rights a person takes part in, as sentences."""
        t = self.t["rights"]
        out = []
        for r in self.ev.rights():
            if pid not in r["people"]:
                continue
            others = [p for p in sorted(r["people"]) if p != pid]
            who = t["with"].format(others=self.names(others)) if others else t["alone"]
            when = t["later"].format(blocks=r["after"], days=round(r["after"] / 144)) if r["after"] else t["now"]
            out.append(t["line"].format(wallet=self.name(r["wallet"]), who=who, when=when))
        return out

    def likelihood(self, L, threat):
        t = self.t["likelihood"]
        lines = [t["category_default" if L["basis"] == "category_default" else "threat"].format(base=L["base"])]
        mods = self.cat.threats[threat].get("likelihood_modifiers", [])
        for i in L.get("modifiers", []):
            lines.append(t["modifier"].format(delta=f"{mods[i]['delta']:+d}", reason=mods[i]["reason"]))
        if "ask" in L:
            lines.append(t["ask"].format(ask=L["ask"]))
        lines.append(t["result"].format(value=L["value"], band=self.band("likelihood", L["value"]),
                                        years=self.ratings["scales"]["likelihood"]["horizon_years"]))
        return lines

    def vulnerability(self, V, sev):
        """(plain lines, measures, text before the measures, text after them)."""
        t = self.t["vulnerability"]
        pre, mechs, lines = [], [], []
        if sev["value"] > 0 and V.get("wallet"):
            pre.append(t["worst"].format(wallet=self.name(V["wallet"])))
        if not V["mechanisms"]:
            pre.append(t["none"])
        for m in V["mechanisms"]:
            mech = self.cat.mechanisms[m["mechanism"]]
            fields = dict(name=mech["name"], effect=t["barrier"] if m.get("barrier") else t["effect"][m["effect"]], entities=self.names(m["entities"]), strength=m["strength"])
            if "minutes" in m:
                fields["effect"] += t["travel"].format(minutes=m["minutes"]) if m["minutes"] is not None else t["travel_alone"]
            note = t["note"][m["note"]] if "note" in m else t["weakened"].format(reason=m["weakened"]) if "weakened" in m else ""
            lines.append(t["mechanism_note"].format(note=note, **fields) if note else t["mechanism"].format(**fields))
            mechs.append({"id": mech["id"], "name": mech["name"], "kind": mech["kind"], "desc": mech["description"],
                          "effect": fields["effect"], "entities": fields["entities"], "strength": m["strength"], "note": note})
        res = t["result"].format(prevention=V["prevention"], detection=V["detection"], value=V["value"],
                                 band=self.band("vulnerability", V["value"]))
        return pre + lines + [res], mechs, pre, res

    def severity(self, S_, outcomes):
        t = self.t["severity"]
        table = self.ratings["outcomes"]
        if S_["value"] == 0:
            return [t["none"]]
        lines = [t["worst"].format(wallet=self.name(o["wallet"]), detail=o["detail"]) for o in outcomes
                 if table[o["outcome"]]["severity"] == S_["value"]]
        others = sorted({self.t["outcomes"][o["outcome"]] for o in outcomes
                         if 0 < table[o["outcome"]]["severity"] < S_["value"]})
        if others:
            lines.append(t["others"].format(outcomes=", ".join(others)))
        label = self.ratings["scales"]["severity"]["bands"][S_["value"]]["label"]
        lines.append(t["result"].format(value=S_["value"], label=label))
        return lines

    def worst_effect(self, S_, outcomes):
        if S_["value"] == 0:
            return self.t["outcomes"]["none"]
        table = self.ratings["outcomes"]
        wallets = sorted({self.name(o["wallet"]) for o in outcomes if table[o["outcome"]]["severity"] == S_["value"]})
        return f"{self.t['outcomes'][S_['outcome']]}: {', '.join(wallets)}"

    def chain(self, row, peers):
        t, S = self.t["chain"], self.S
        threat = self.cat.threats[row["threat"]]
        ents = row["entity"] if isinstance(row["entity"], list) else [row["entity"]]
        lines = [t["threat"].format(threat=threat["name"], **{"class": self.t["classes"][row["class"]][0].lower()},
                                    entity=self.names(ents), description=threat["description"])]
        if peers:
            lines.append(t["peers"].format(peers=self.names(peers)))
        for kind, ids in row.get("effects", {}).items():
            if kind in self.t["effects"]:
                lines.append(t["effect"].format(label=self.t["effects"][kind], entities=self.names(ids)))
        for o in row["outcomes"]:
            exploit = self.t["exploit"][o["exploit"]]
            lines.append(t["outcome"].format(wallet=self.name(o["wallet"]), label=self.t["outcomes"][o["outcome"]].lower(),
                                             detail=o["detail"], exploit=f"; {exploit}" if exploit else ""))
        for a in row.get("access", []):
            lines.append(self.t["access"][a["result"]].format(person=self.name(a["person"]), wallet=self.name(a["wallet"])))
        risk = self.t["risk"]["result"].format(L=row["L"]["value"], V=row["V"]["value"], RL=row["RL"], S=row["S"]["value"],
                                               R=row["R"], label=self.t["risk_labels"][row["R"]])
        return lines, risk

    def open_items(self, row):
        out = []
        for n in row.get("needs_input", []):
            out.append(self.t["chain"]["open"].format(text=n[4:] if n.startswith("ask:") else self.t["needs_input"].get(n, n)))
        return out

    def not_applicable(self, na):
        reason, _, arg = na["reason"].partition(":")
        text = self.t["not_applicable"][reason].format(name=arg)
        ents = [na["entity"]]
        return {"t": na["threat"], "tn": self.cat.threats[na["threat"]]["name"], "e": ents, "en": self.names(ents, 3),
                "c": self.S.cls(na["entity"]), "why": text}


def schedule_text(texts, sched):
    t, parts = texts["schedule"], []
    for key in ("every_months", "every_fraction_of_delay"):
        if key in sched:
            parts.append(t[key].format(n=sched[key]))
    if "trigger" in sched:
        parts.append(t["trigger"][sched["trigger"]])
    return ", ".join(parts)


def steps_of(cat, texts, aid, trail=(), depth=3):
    """A recovery action with its nested steps; composites are expanded a few levels, a repeated action is not expanded again."""
    a = cat.actions.get(aid)
    if a is None:
        return None
    node = {"name": a["name"], "desc": a["description"]}
    if a["type"] == "composite" and depth and aid not in trail:
        node["how"] = texts["procedure"][a["combinator"]]
        node["steps"] = [n for s in a["steps"] if (n := steps_of(cat, texts, s["action"], trail + (aid,), depth - 1))]
    return node


def measures_view(result, S, cat, w, texts, rows):
    """Procedural measures in place and missing ones, with the rows whose rating they change."""
    by_id = {r["id"]: r for r in rows}
    practices = {p["id"]: p for p in S.data.get("practices", [])}

    def lines(changes):
        return [{"id": i, "tn": by_id[i]["tn"], "en": by_id[i]["en"], "R": r0, "R2": r1, "V": v0, "V2": v1}
                for i, r0, r1, v0, v1 in changes]
    out = []
    for m in result["measures"]:
        mech = cat.mechanisms[m["mechanism"]]
        p = practices.get(m.get("practice"))
        sched = rating.effective_schedule(mech, p)
        parent = cat.mechanisms.get(mech.get("refines"))
        item = {"id": mech["id"], "name": mech["name"], "desc": mech["description"], "kind": mech["kind"],
                "group": {"id": parent["id"], "name": parent["name"], "desc": parent["description"]} if parent else None,
                "steps": [n for n in (steps_of(cat, texts, a) for a in mech.get("procedure", [])) if n],
                "when": schedule_text(texts, sched), "inplace": p is not None or "implicit" in m,
                "applicable": [w.name(e) for e in m["applicable"]],
                "addresses": sorted({cat.threats[a["threat"]]["name"] for a in mech["addresses"]}),
                "lines": lines(m["rows"])}
        if p is not None:
            item.update({"practice": p["id"], "scope": [w.name(e) for e in m["scope"]], "uncovered": [w.name(e) for e in m["uncovered"]],
                         "comment": m.get("comment", ""), "extend": lines(m.get("extend", []))})
        elif "implicit" in m:
            item.update({"byuse": True, "scope": [w.name(e) for e in m["implicit"]], "uncovered": [], "comment": texts["measures"]["by_use"], "extend": []})
        out.append(item)
    return out


def modifier_sum(cat, threat, L):
    mods = cat.threats[threat].get("likelihood_modifiers", [])
    return sum(mods[i]["delta"] for i in L.get("modifiers", []))


def rights_view(result):
    """Intended rights against the intact setup, and how many threats delay or cost each person's access to a wallet."""
    hit = {}
    for r in result["rows"]:
        for a in r.get("access", []):
            hit.setdefault((a["person"], a["wallet"]), {"delayed": 0, "lost": 0})[a["result"]] += 1
    base = result.get("rights", {"rights": [], "extra": []})
    return dict(base, threats=[{"person": p, "wallet": w, **n} for (p, w), n in sorted(hit.items())])


def build_data(result, S, cat, images=False):
    texts = loader.read_json(cat.data_dir / "Texts.json")
    ev = outcomes.Evaluator(S)
    w = Writer(S, ev, cat, texts)
    rows = []
    for r in result["rows"]:
        ents = r["entity"] if isinstance(r["entity"], list) else [r["entity"]]
        steps, risk = w.chain(r, r.get("common_cause", []))
        affected = set()
        for k, v in r.get("effects", {}).items():
            if isinstance(v, list):
                affected |= set(v)
        mech = {e for m in r["V"]["mechanisms"] for e in m["entities"]}
        wallets = {o["wallet"] for o in r["outcomes"] if o["outcome"] != "none"}
        vx, vm, vpre, vres = w.vulnerability(r["V"], r["S"])
        ctx, pols = context(S, set(ents) | affected | set(r.get("common_cause", [])), wallets)
        rows.append({
            "id": r["id"], "t": r["threat"], "tn": cat.threats[r["threat"]]["name"], "e": ents, "en": w.names(ents, 3),
            "c": r["class"], "eff": w.worst_effect(r["S"], r["outcomes"]),
            "L": {"v": r["L"]["value"], "x": w.likelihood(r["L"], r["threat"]), "cb": r["L"].get("catalog_base", r["L"]["base"]), "mod": modifier_sum(cat, r["threat"], r["L"]),
                  "ask": r["L"].get("asked")},
            "V": {"v": r["V"]["value"], "x": vx, "m": vm, "pre": vpre, "res": vres, "c": r["V"].get("computed", r["V"]["value"])},
            "S": {"v": r["S"]["value"], "x": w.severity(r["S"], r["outcomes"]), "c": r["S"].get("computed", r["S"]["value"])},
            "RL": r["RL"], "R": r["R"], "chain": steps + w.open_items(r), "risk": risk,
            "rel": {"target": ents, "affected": sorted(affected - set(ents)), "peers": r.get("common_cause", []),
                    "wallets": sorted(wallets), "mech": sorted(mech), "context": ctx, "policies": pols},
        })
    order = [eid for c in CLASS_ORDER for eid in sorted(S.ids_of(c), key=lambda e: not ev.is_main(e) if c == "Wallet" else False)]
    return {
        "meta": result["meta"], "warnings": result["warnings"], "asks": result["asks"],
        "overrides": result.get("overrides", []),
        "rights": rights_view(result),
        "texts": {k: texts[k] for k in ("classes", "risk_labels", "outcomes", "display", "subject_of")},
        "roles": {"actor": S.model["actor"]["class"], "asset": S.model["asset"]["class"]},
        "scales": {k: {"description": v["description"], "bands": [b.get("probability") or b["label"] for b in v["bands"]]}
                   for k, v in cat.ratings["scales"].items()},
        "risk_matrix": cat.ratings["risk_matrix"]["values"], "residual": cat.ratings["residual_likelihood"]["formula"],
        "entities": [{"id": e, "name": w.name(e), "class": S.cls(e)} for e in order],
        "rows": rows, "na": [w.not_applicable(n) for n in result["not_applicable"]],
        "measures": measures_view(result, S, cat, w, texts, rows),
        "deductive": result.get("deductive", []),
        "structure": structure(S, ev, w, texts, images),
    }


def render_html(result, setup_path, images=False, cat=None):
    cat = cat or loader.Catalogs()
    data = build_data(result, Setup(loader.read_json(setup_path), cat), cat, images)
    payload = json.dumps(data, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
    return TEMPLATE.read_text(encoding="utf-8").replace("__DATA__", payload)


def write_html(result, setup_path, path, images=False, cat=None):
    Path(path).write_text(render_html(result, setup_path, images, cat), encoding="utf-8")
