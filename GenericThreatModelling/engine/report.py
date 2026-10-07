"""HTML report of an analysis: classic table and the setup diagram coloured by risk, in one offline file.
The texts come from Texts.json; the page draws the diagram itself from the structure data."""
import base64
import json
from pathlib import Path

import loader
import effects
import rating
from model import PERSON_PLACE, Setup
import ontology
from ontology import is_a

ENGINE = Path(__file__).resolve().parent
TEMPLATE = ENGINE / "report.template.html"
IMAGES = loader.LOOKUPS / "DeviceImages" / "thumb"
CLASS_ORDER = ontology.CONCRETE


def secrets_in(S, eid):
    """What one finds by opening a backup or holding a device."""
    c = S.cls(eid)
    if c == "Backup":
        out = set()
        for item in S.ent(eid)["items"]:
            out |= {"@plan" if k == "plan" else v for k, v in item["subject"].items()}
        return out
    if is_a(c, "Device"):
        return set(S.seeds_on(eid)) | set(S.ent(eid).get("stores_descriptors", [])) | {d for co in S.coordinators_on(eid) for d in S.ent(co).get("stores_descriptors", [])}
    return set()


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


def spendable(S, pid):
    """The wallets and spending policies (`wallet#n`) that the person can satisfy alone, or together with the others of a right to that wallet, whatever the delay."""
    out = set()
    tries = [(None, {pid})] + [(r["wallet"], set(r["people"])) for r in S.rights() if pid in r["people"]]
    for only, group in tries:
        owner = effects.Owner(S, effects.State(), True, group)
        for wal in S.of("Wallet"):
            if only and wal["id"] != only or not owner.descriptor_ok(wal["id"]):
                continue
            for i, pol in enumerate(wal["spending_policies"], 1):
                if sum(owner.signer_ok(sg) for sg in pol["signers"]) >= pol["threshold"]:
                    out |= {wal["id"], f"{wal['id']}#{i}"}
    return out


def implicit_id(wid):
    return f"implicit:{wid}"


def coordinator_holds(S, w, cid):
    """The descriptors a coordinator has: kept explicitly, or derived on its host from the seeds that are there (implicit)."""
    kept, out = S.ent(cid).get("stores_descriptors", []), []
    for wal in S.of("Wallet"):
        did = wal.get("descriptor")
        if did in kept:
            out.append({"id": did, "name": w.name(did), "c": "Descriptor", "tip": f"descriptor {w.name(did)} is kept by this coordinator"})
        elif S.has_descriptor(cid, wal["id"]):
            out.append({"id": did or implicit_id(wal["id"]), "name": w.name(did) if did else f"Descriptor of {w.name(wal['id'])}", "c": "Descriptor", "implicit": True,
                        "tip": f"the descriptor of {w.name(wal['id'])} is derived on this host from the seeds that are there"})
    return out


def structure(S, w, images=False):
    """The setup as plain data for the diagram: cards, links, and what each person can reach."""
    def sub(c, e):
        if c == "SigningDevice":
            return f"{e['vendor']} {e['model']}"
        if c == "ComputingDevice":
            return e["kind"] + (f", {e['product']}" if "product" in e else "")
        if c == "Backup":
            return e["medium"].replace("_", " ") + (f", {e['product']['vendor']} {e['product']['model']}" if "product" in e else "")
        if c == "Location":
            return e["kind"].replace("_", " ")
        if c == "Person":
            return ", ".join(e.get("roles", []))
        if c == "Coordinator":
            return e.get("product", "")
        return ""
    nodes = []
    pictures, of = device_images(S) if images else ({}, {})
    for eid, (c, e) in S.by_id.items():
        if eid.startswith(PERSON_PLACE):
            continue
        node = {"id": eid, "c": c, "name": w.name(eid), "sub": sub(c, e)}
        if eid in of:
            node["img"], node["imgmatch"] = of[eid]["file"], of[eid]["match"]
        if is_a(c, "Device"):
            node["holds"] = [{"id": s, "name": w.name(s), "c": S.cls(s),
                              "tip": f"{'seed' if S.cls(s) == 'Seed' else 'descriptor'} {w.name(s)} is {'loaded' if S.cls(s) == 'Seed' else 'stored'} on this device"}
                             for s in S.seeds_on(eid) + list(e.get("stores_descriptors", []))]
        if c == "Coordinator":
            node["holds"] = coordinator_holds(S, w, eid)
        if c == "Person":
            node["may"] = w.rights_of(eid)
        if c == "Backup":
            node["subjects"] = sorted({k for item in e["items"] for k in item["subject"]})
        if c == "Location" and e.get("part_of"):
            node["in"] = e["part_of"]
        elif "stored_in" in e:
            where = e["stored_in"]
            node["in"] = where["person"] if "person" in where else next(iter(where.values()))
        elif c == "Coordinator" and "runs_on" in e:
            node["in"] = e["runs_on"]
        if c == "Wallet":
            node["custom"] = e["definition"] == "custom"
            node["tripwire"] = bool(e.get("tripwire", {}).get("enabled"))
            node["policies"] = [f"{p['threshold']} of {len(p['signers'])}, " + (f"after {p['delay_blocks']} blocks" if p["delay_blocks"] else "at once")
                                for p in e["spending_policies"]]
        nodes.append(node)
    nodes += [{"id": implicit_id(wal["id"]), "c": "Descriptor", "name": f"Descriptor of {w.name(wal['id'])}", "sub": "derived from the keys", "implicit": True}
              for wal in S.of("Wallet") if "descriptor" not in wal]
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
        edges.append([wal["id"], wal.get("descriptor", implicit_id(wal["id"])), "descriptor"])
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
    access, spend = {}, {}
    for p in S.ids_of("Person"):
        items = set(S.reachable_entities(p))
        got = set().union(*[secrets_in(S, e) for e in items]) if items else set()
        spend[p] = spendable(S, p)
        access[p] = sorted({p} | {x for x in S.reach(p) if not x.startswith(PERSON_PLACE)} | items | got | spend[p])
    who, deps = {}, {}
    for wid in S.ids_of("Wallet"):
        who[wid] = sorted({p for p in S.ids_of("Person") if wid in spend[p]} | {p for r in S.rights() if r["wallet"] == wid for p in r["people"]})
        deps[wid] = sorted(S.deps(wid))
        if len(S.ent(wid)["spending_policies"]) > 1:
            for i in range(len(S.ent(wid)["spending_policies"])):
                who[f"{wid}#{i + 1}"] = sorted(p for p in S.ids_of("Person") if f"{wid}#{i + 1}" in spend[p])
                deps[f"{wid}#{i + 1}"] = sorted(S.deps(wid, i))
    return {"nodes": nodes, "edges": edges, "access": access, "who": who, "images": pictures, "deps": deps}


def context(S, chain, wallets):
    """Seeds, descriptors and spending policies that link the affected entities to the wallets."""
    nodes, policies = set(), []
    for wid in wallets:
        if wid not in S.by_id or S.cls(wid) != "Wallet":
            continue
        for i, p in enumerate(S.ent(wid)["spending_policies"], 1):
            hit = False
            for sg in p["signers"]:
                parts = {sg["seed"]} | ({sg["passphrase"]} if "passphrase" in sg else set())
                carriers = set(S.ent(sg["seed"]).get("devices", [])) | {b for b, _ in S.copies(sg["seed"])}
                if "passphrase" in sg:
                    carriers |= {b for b, _ in S.copies(sg["passphrase"])}
                if (parts | carriers) & chain:
                    nodes |= parts
                    hit = True
            if hit:
                policies.append(f"{wid}#{i}")
        d = S.ent(wid).get("descriptor")
        if d and ({d} | {b for b, _ in S.copies(d)} | set(S.devices_storing(d))) & chain:
            nodes.add(d)
    return sorted(nodes - chain), policies


class Writer:
    def __init__(self, S, cat, texts):
        self.S, self.cat, self.t = S, cat, texts
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
        for r in self.S.rights():
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
            if kind in self.t["effects"] and isinstance(ids, list):
                lines.append(t["effect"].format(label=self.t["effects"][kind], entities=self.names(ids)))
            elif kind in self.t["effects"]:
                lines.append(self.t["effects"][kind] + ".")
        for w, flags in row.get("effects", {}).get("wallet_flags", {}).items():
            lines.append(t["flag"].format(wallet=self.name(w), flags=", ".join(self.t["wallet_flags"][f] for f in flags)))
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
    texts = loader.read_json(loader.DATA / "Texts.json")
    w = Writer(S, cat, texts)
    rows = []
    for r in result["rows"]:
        ents = r["entity"] if isinstance(r["entity"], list) else [r["entity"]]
        steps, risk = w.chain(r, r.get("common_cause", []))
        affected = set()
        for k, v in r.get("effects", {}).items():
            if isinstance(v, list):
                affected |= set(v)
        mech = {e for m in r["V"]["mechanisms"] for e in m["entities"]}
        wallets = {o["wallet"] for o in r["outcomes"] if o["outcome"] != "none"} | set(r.get("effects", {}).get("wallet_flags", {}))
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
    order = [eid for c in CLASS_ORDER for eid in sorted(S.ids_of(c), key=lambda e: not S.is_main(e) if c == "Wallet" else False)]
    return {
        "meta": result["meta"], "warnings": result["warnings"], "asks": result["asks"],
        "overrides": result.get("overrides", []),
        "rights": rights_view(result),
        "texts": {k: texts[k] for k in ("classes", "risk_labels", "outcomes")},
        "scales": {k: {"description": v["description"], "bands": [b.get("probability") or b["label"] for b in v["bands"]]}
                   for k, v in cat.ratings["scales"].items()},
        "risk_matrix": cat.ratings["risk_matrix"]["values"], "residual": cat.ratings["residual_likelihood"]["formula"],
        "entities": [{"id": e, "name": w.name(e), "class": S.cls(e)} for e in order],
        "rows": rows, "na": [w.not_applicable(n) for n in result["not_applicable"]],
        "measures": measures_view(result, S, cat, w, texts, rows),
        "structure": structure(S, w, images),
    }


def render_html(result, setup_path, images=False):
    cat = loader.Catalogs()
    data = build_data(result, Setup(loader.read_json(setup_path), cat), cat, images)
    payload = json.dumps(data, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
    return TEMPLATE.read_text(encoding="utf-8").replace("__DATA__", payload)


def write_html(result, setup_path, path, images=False):
    Path(path).write_text(render_html(result, setup_path, images), encoding="utf-8")
