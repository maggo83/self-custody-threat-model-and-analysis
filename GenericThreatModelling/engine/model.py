"""The setup as a graph: containment, reach, secret copies, dependencies, attribute conditions."""
import copy
import json
import re
from functools import lru_cache
from itertools import combinations, permutations, product

from ontology import COLLECTIONS, STORABLE, SUBCLASSES, is_a

INF = float("inf")

PERSON_PLACE = "person:"
PLAN = "@plan"


def canon(v):
    return json.dumps(v, sort_keys=True) if isinstance(v, (dict, list)) else v


def resolve(entity, path):
    """Values of a dotted path; `name[]` walks a list. Lists at the end are flattened."""
    cur = [entity]
    for part in path.split("."):
        walk = part.endswith("[]")
        key = part[:-2] if walk else part
        nxt = []
        for c in cur:
            if isinstance(c, dict) and key in c:
                v = c[key]
                nxt.extend(v if walk and isinstance(v, list) else [v])
        cur = nxt
    out = []
    for v in cur:
        out.extend(v if isinstance(v, list) else [v])
    return [canon(v) for v in out if v not in (None, "")]


def cond_ok(values, c):
    """One condition on resolved values; missing counts as not satisfying in/matches."""
    if "in" in c:
        return any(v in c["in"] for v in values)
    if "not_in" in c:
        return not any(v in c["not_in"] for v in values)
    if "matches" in c:
        return any(re.search(c["matches"], str(v)) for v in values)
    return not any(re.search(c["not_matches"], str(v)) for v in values)


class Setup:
    def __init__(self, data, cat):
        self.data, self.cat = self._with_defaults(data), cat
        data = self.data
        self.plan = {"id": PLAN, "name": data["name"]}
        self.by_id = {PLAN: ("Plan", self.plan)}
        for c, coll in COLLECTIONS.items():
            for e in data.get(coll, []):
                self.by_id[e["id"]] = (c, e)
        self._loc, self._bags = {}, {}
        for eid, (c, e) in list(self.by_id.items()):
            if c in STORABLE:
                bags, cur = [], e["stored_in"]
                while "bag" in cur:
                    bags.append(cur["bag"])
                    cur = self.ent(cur["bag"])["stored_in"]
                self._loc[eid] = cur["location"] if "location" in cur else self._person_place(cur["person"])
                self._bags[eid] = bags[::-1]          # outermost first
        self._children = {}
        for l in self.of("Location"):
            self._children.setdefault(l.get("part_of"), []).append(l["id"])

    def _person_place(self, pid):
        """What a person keeps in mind or carries is in a place of its own, which only that person can reach."""
        place = PERSON_PLACE + pid
        if place not in self.by_id:
            name = self.ent(pid).get("name", pid)
            self.by_id[place] = ("Location", {"id": place, "name": f"{name}: memory and what is carried", "kind": "person", "access": [pid]})
        return place

    @staticmethod
    def _with_defaults(data):
        """A copy in which the defaults of the setup schema are filled in, so that conditions and groups see them."""
        data = copy.deepcopy(data)
        for seed in data.get("seeds", []):
            seed.setdefault("scheme", "bip39")
            seed.setdefault("word_count", 12)
        for w in data.get("wallets", []):
            w.setdefault("definition", "default")
            for p in w["spending_policies"]:
                p.setdefault("delay_blocks", 0)
        for d in data.get("devices", []):
            d.setdefault("online", False)
        for d in data.get("computing_devices", []):
            d.setdefault("online", True)
        by_wallet = {d["wallet"]: d["id"] for d in data.get("descriptors", [])}
        for w in data.get("wallets", []):
            if w["id"] in by_wallet:
                w["descriptor"] = by_wallet[w["id"]]
        for b in data.get("backups", []):
            for item in b["items"]:
                if "seed" in item["subject"]:
                    item.setdefault("format", "words")
        return data

    # basic access
    def cls(self, eid):
        return self.by_id[eid][0]

    def ent(self, eid):
        return self.by_id[eid][1]

    def of(self, cls):
        if cls == "Plan":
            return [self.plan]
        if cls in SUBCLASSES:
            return [e for c in SUBCLASSES[cls] for e in self.data.get(COLLECTIONS[c], [])]
        return self.data.get(COLLECTIONS[cls], [])

    def ids_of(self, cls):
        return [e["id"] for e in self.of(cls)]

    # containment
    def loc_of(self, eid):
        return self._loc.get(eid)

    def enclosing_bags(self, eid):
        return self._bags.get(eid, [])

    def root(self, loc):
        while self.ent(loc).get("part_of"):
            loc = self.ent(loc)["part_of"]
        return loc

    @lru_cache(None)
    def subtree(self, loc):
        out = {loc}
        for c in self._children.get(loc, []):
            out |= self.subtree(c)
        return frozenset(out)

    def contents(self, loc):
        sub = self.subtree(loc)
        return [e for e, l in self._loc.items() if l in sub]

    def bag_contents(self, bag):
        return [e for e, bags in self._bags.items() if bag in bags]

    def area(self, loc):
        """Locations hit by the same area-wide event: the whole building tree plus near-linked trees."""
        near = {}
        for l in self.of("Location"):
            for n in l.get("near", []):
                near.setdefault(l["id"], set()).add(n)
                near.setdefault(n, set()).add(l["id"])
        trees = set(self.subtree(self.root(loc)))
        for member in list(trees):
            for n in near.get(member, ()):
                trees |= self.subtree(self.root(n))
        return trees

    def area_contents(self, loc):
        locs = self.area(loc)
        return [e for e, l in self._loc.items() if l in locs]

    # people
    @lru_cache(None)
    def reach(self, pid):
        """Locations the person can physically reach; a sub-location also needs access to its parent."""
        def ok(loc):
            e = self.ent(loc)
            return pid in e.get("access", []) and (not e.get("part_of") or ok(e["part_of"]))
        mine = PERSON_PLACE + pid
        return frozenset(l["id"] for l in self.of("Location") if ok(l["id"])) | ({mine} if mine in self.by_id else set())

    def reachable_entities(self, pid):
        r = self.reach(pid)
        return [e for e, l in self._loc.items() if l in r]

    def concealed(self, loc):
        row = self.catalog_row(loc)
        return bool(row) and row["concealment"].startswith("secret")

    def visible_locations(self, loc):
        out = {loc}
        for c in self._children.get(loc, []):
            if not self.concealed(c):
                out |= self.visible_locations(c)
        return out

    def intrusion_contents(self, loc):
        """What an intruder finds: all that is in view; a concealed place only if it is the target, then with what is in view above it."""
        locs = set(self.subtree(loc)) if self.concealed(loc) else self.visible_locations(loc)
        up = self.ent(loc).get("part_of")
        while self.concealed(loc) and up:
            locs |= self.visible_locations(up)
            up = self.ent(up).get("part_of")
        return [e for e, l in self._loc.items() if l in locs]

    # travel
    @lru_cache(None)
    def travel_table(self):
        """Shortest declared travel time in minutes between top-level places; an undeclared pair counts as 0 (no protection)."""
        roots = [l["id"] for l in self.of("Location") if not l.get("part_of")]
        d = {(a, b): 0 for a in roots for b in roots}
        for t in self.data.get("travel_times", []):
            a, b = self.root(t["from"]), self.root(t["to"])
            d[(a, b)] = d[(b, a)] = t["minutes"]
        return d

    def travel(self, a, b):
        return self.travel_table().get((self.root(a), self.root(b)), 0)

    def _journey(self, stops):
        stops = list(stops)
        if len(stops) < 2:
            return 0
        return min(sum(self.travel(a, b) for a, b in zip(p, p[1:])) for p in permutations(stops))

    def _stops(self, sid, reach):
        """Places where a person can get at a secret; None = somewhere they carry along (memory, cloud)."""
        out = set()
        for l in self.secret_locations(sid):
            if l in reach:
                out.add(None if self.cat.location_rows[(self.ent(l)["kind"],)]["remote"] == "yes" else self.root(l))
        return out

    def quorum_minutes(self, pid):
        """Least time the person needs to bring together signers that can spend at once on a main wallet, starting at the best place; INF if they cannot alone."""
        reach, best = self.reach(pid), INF
        for w in self.of("Wallet"):
            if not self.is_main(w["id"]):
                continue
            for pol in w["spending_policies"]:
                if pol["delay_blocks"]:
                    continue
                options = []
                for sg in pol["signers"]:
                    seeds = self._stops(sg["seed"], reach)
                    keys = self._stops(sg["passphrase"], reach) if "passphrase" in sg else {None}
                    if seeds and keys:
                        options.append([frozenset(x for x in (a, b) if x) for a in seeds for b in keys])
                for chosen in combinations(options, pol["threshold"]):
                    for pick in product(*chosen):
                        best = min(best, self._journey(frozenset().union(*pick)))
        return best

    # access rights
    @lru_cache(None)
    def rights(self):
        """Who may spend a wallet after how long: one entry per (set of people, wallet) with the smallest declared delay."""
        mains = [w for w in self.ids_of("Wallet") if self.is_main(w)]
        found = {}
        for p in self.of("Person"):
            for e in p.get("may_spend", []):
                people = frozenset([p["id"], *e.get("with", [])])
                for w in e.get("wallets", mains):
                    found[(people, w)] = min(found.get((people, w), INF), e.get("after_blocks", 0))
        out = [{"people": ppl, "wallet": w, "after": d} for (ppl, w), d in found.items()]
        return tuple(sorted(out, key=lambda r: (r["wallet"], r["after"], sorted(r["people"]))))

    def is_owner(self, pid):
        return "owner" in self.ent(pid).get("roles", [])

    def memory_holders(self, bid):
        loc = self.ent(self.loc_of(bid))
        return loc.get("access", []) if loc["kind"] == "person" else []

    def memory_backups(self, pid):
        return [b["id"] for b in self.of("Backup") if b["medium"] == "memory" and pid in self.memory_holders(b["id"])]

    # secrets
    @lru_cache(None)
    def copies(self, sid):
        out = []
        for b in self.of("Backup"):
            for item in b["items"]:
                if sid in item["subject"].values():
                    out.append((b["id"], item))
        return tuple(out)

    def descriptor_is_custom(self, wid):
        return self.ent(wid)["definition"] == "custom"

    def seeds_on(self, did):
        return [s["id"] for s in self.of("Seed") if did in s.get("devices", [])]

    def devices_storing(self, desc):
        return [d["id"] for d in self.of("Device") if desc in d.get("stores_descriptors", [])]

    def coordinators_on(self, did):
        return [c["id"] for c in self.of("Coordinator") if c.get("runs_on") == did]

    def coordinators_storing(self, desc):
        return [c["id"] for c in self.of("Coordinator") if desc in c.get("stores_descriptors", [])]

    def has_descriptor(self, cid, wid):
        """The coordinator has the wallet's descriptor: an explicit copy, or implicitly because its host holds the seeds of a default wallet."""
        d = self.ent(wid).get("descriptor")
        if d and d in self.ent(cid).get("stores_descriptors", []):
            return True
        if self.descriptor_is_custom(wid):
            return False
        host = self.ent(cid)["runs_on"]
        return all(host in self.ent(sg["seed"]).get("devices", []) for _, _, sg in self.signers(wid))

    def coordinators_of(self, wid):
        return [c["id"] for c in self.of("Coordinator") if self.has_descriptor(c["id"], wid)]

    def secret_roots(self, sid):
        """Root locations that hold a copy (backups, and devices for seeds, descriptors)."""
        locs = {self.loc_of(b) for b, _ in self.copies(sid)}
        if self.cls(sid) == "Seed":
            locs |= {self.loc_of(d) for d in self.ent(sid).get("devices", [])}
        if self.cls(sid) == "Descriptor":
            locs |= {self.loc_of(d) for d in self.devices_storing(sid)}
            locs |= {self.loc_of(self.ent(c)["runs_on"]) for c in self.coordinators_storing(sid)}
        return {self.root(l) for l in locs}

    def secret_locations(self, sid):
        locs = {self.loc_of(b) for b, _ in self.copies(sid)}
        if self.cls(sid) == "Seed":
            locs |= {self.loc_of(d) for d in self.ent(sid).get("devices", [])}
        return locs

    # wallets
    def signers(self, wid):
        return [(i, p, sg) for i, p in enumerate(self.ent(wid)["spending_policies"]) for sg in p["signers"]]

    def is_main(self, wid):
        return not self.ent(wid).get("tripwire", {}).get("enabled", False)

    def needs_registration(self, wid):
        """A device cannot derive the descriptor alone: several signers, or a custom definition."""
        signers = {(sg["seed"], sg.get("passphrase")) for _, _, sg in self.signers(wid)}
        return len(signers) > 1 or self.descriptor_is_custom(wid)

    def registration_wallets(self, did):
        return [w for w in self.dependent_wallets(did) if self.needs_registration(w)]

    def registration_support(self, did):
        """registers, per_transaction, none or unknown; unknown (also a missing catalog row) counts as none."""
        v = (self.catalog_row(did) or {}).get("descriptor_registration")
        return v if v in ("registers", "per_transaction", "none") else "unknown"

    def quorum_covered(self, wid, devices):
        """Every group of signers that can spend under one policy has a member whose devices all are in `devices`."""
        for p in self.ent(wid)["spending_policies"]:
            uncovered = 0
            for sg in p["signers"]:
                ds = set(self.ent(sg["seed"]).get("devices", []))
                uncovered += not ds or not ds <= set(devices)
            if uncovered >= p["threshold"]:
                return False
        return True

    def dependent_wallets(self, eid):
        c = self.cls(eid)
        out = []
        for w in self.of("Wallet"):
            seeds = {sg["seed"] for _, _, sg in self.signers(w["id"])}
            hosts = any(self.has_descriptor(co, w["id"]) for co in self.coordinators_on(eid)) if is_a(c, "Device") else False
            if is_a(c, "Device") and (hosts or any(eid in self.ent(s).get("devices", []) for s in seeds)):
                out.append(w["id"])
            elif c == "Coordinator" and self.has_descriptor(eid, w["id"]):
                out.append(w["id"])
            elif c == "Descriptor" and w.get("descriptor") == eid:
                out.append(w["id"])
            elif c == "Seed" and eid in seeds:
                out.append(w["id"])
            elif c == "Wallet" and w["id"] == eid:
                out.append(w["id"])
        return out

    @lru_cache(None)
    def deps(self, wid, policy=None):
        """Everything the wallet's use depends on, including enclosing bags and their strips; with `policy` (0-based) only what that spending policy needs."""
        ids = {wid}

        def add_entity(eid):
            ids.add(eid)
            for b in self.enclosing_bags(eid):
                ids.add(b)
                ids.add(self.ent(b)["strip"])

        def add_secret(sid):
            ids.add(sid)
            for bk, _ in self.copies(sid):
                add_entity(bk)
            if self.cls(sid) == "Seed":
                for d in self.ent(sid).get("devices", []):
                    add_device(d)
            if self.cls(sid) == "Descriptor":
                for d in self.devices_storing(sid):
                    add_device(d)
                for co in self.coordinators_storing(sid):
                    add_coordinator(co)

        def add_coordinator(cid):
            ids.add(cid)
            if self.ent(cid).get("password"):
                add_secret(self.ent(cid)["password"])
            add_device(self.ent(cid)["runs_on"])

        def add_device(did):
            add_entity(did)
            if self.ent(did).get("pin"):
                add_secret(self.ent(did)["pin"])

        w = self.ent(wid)
        for i, _, sg in self.signers(wid):
            if policy is not None and i != policy:
                continue
            add_secret(sg["seed"])
            if "passphrase" in sg:
                add_secret(sg["passphrase"])
        if w.get("descriptor"):
            add_secret(w["descriptor"])
        for co in self.coordinators_of(wid):
            add_coordinator(co)
        return frozenset(ids)

    # attributes and conditions
    def catalog_row(self, eid):
        c, e = self.by_id[eid]
        cat = self.cat
        if c == "SigningDevice":
            return cat.device_rows.get((e["vendor"], e["model"]))
        if c == "Backup" and "product" in e:
            return cat.metal_rows.get((e["product"]["vendor"], e["product"]["model"]))
        if c == "Location":
            return cat.location_rows.get((e["kind"],))
        return None

    def values(self, eid, path):
        if path.startswith("catalog."):
            row = self.catalog_row(eid)
            v = row.get(path[8:]) if row else None
            return [v] if v not in (None, "") else []
        return resolve(self.ent(eid), path)

    def holds(self, eid, conditions):
        return all(cond_ok(self.values(eid, c["path"]), c) for c in conditions or [])

    def group_key(self, eid, paths):
        return tuple(tuple(sorted(map(str, self.values(eid, p)))) for p in paths)
