"""Threat effects on a setup and their evaluation: what can the people still do, what can an attacker do."""
from collections import defaultdict
from itertools import combinations

from model import INF, PLAN
from ontology import CREDENTIALS, is_a
from predicates import descriptor_known
from vocab import LEAK


class State:
    SETS = ("lost", "blocked", "disclosed", "controlled", "tampered", "secret_lost", "secret_blocked", "secret_known", "touched")

    def __init__(self):
        for f in self.SETS:
            setattr(self, f, set())
        self.flags = defaultdict(set)      # wallet -> {'tamper', 'privacy', 'blocked', 'soft'}
        self.privacy = False
        self.plan_impaired = False
        self.actors = set()                 # persons who act against the setup themselves

    def copy(self):
        n = State()
        for f in self.SETS:
            setattr(n, f, set(getattr(self, f)))
        n.flags = defaultdict(set, {k: set(v) for k, v in self.flags.items()})
        n.privacy, n.plan_impaired = self.privacy, self.plan_impaired
        n.actors = set(self.actors)
        return n

    def summary(self):
        out = {f: sorted(getattr(self, f)) for f in self.SETS if getattr(self, f)}
        if self.flags:
            out["wallet_flags"] = {k: sorted(v) for k, v in sorted(self.flags.items())}
        if self.privacy:
            out["privacy"] = True
        if self.plan_impaired:
            out["plan_impaired"] = True
        return out

    def ids(self):
        out = set()
        for f in self.SETS:
            out |= getattr(self, f)
        return out | set(self.flags)


# ---------------------------------------------------------------- applying effects

def hit(S, st, eid, kind, malicious=True):
    """Effect `kind` on one entity. A tampering without a malicious actor is an error: the part is simply wrong."""
    c = S.cls(eid)
    if kind == "tampered" and not malicious and (c in ("Backup", "Descriptor") or is_a(c, "Device")):
        kind = "destroyed"
    if c == "Person":
        if kind in ("destroyed", "unavailable"):
            st.lost.add(eid)
        elif kind in LEAK:
            st.privacy = True
    elif is_a(c, "Device"):
        if kind == "destroyed":
            st.lost.add(eid)
        elif kind == "unavailable":
            st.blocked.add(eid)
        elif kind in LEAK:
            st.disclosed.add(eid)
        else:
            st.controlled.add(eid)
        for co in S.coordinators_on(eid):
            st.touched.add(co)
            if kind not in LEAK:                # what a leak gives away follows from attacker_secrets
                apply_impact(S, st, co, {"on": "wallets", "kind": kind}, malicious)
    elif c == "Backup":
        if kind == "destroyed":
            st.lost.add(eid)
        elif kind == "unavailable":
            st.blocked.add(eid)
        elif kind in LEAK:
            st.disclosed.add(eid)
        elif kind == "tampered":
            st.tampered.add(eid)
    elif c in CREDENTIALS:
        if kind in LEAK:
            st.secret_known.add(eid)
        elif kind == "destroyed":
            st.secret_lost.add(eid)
        elif kind == "unavailable":
            st.secret_blocked.add(eid)
    elif c == "Descriptor":
        if kind in LEAK:
            st.secret_known.add(eid)
        elif kind == "destroyed":
            st.lost.add(eid)
        elif kind == "unavailable":
            st.blocked.add(eid)
        elif kind == "tampered":
            st.tampered.add(eid)
    elif c == "Wallet":
        if kind in ("tampered", "controlled"):
            st.flags[eid].add("tamper" if malicious else "tamper_latent")
        elif kind in ("unavailable", "destroyed"):
            st.flags[eid].add("blocked")
        elif kind in LEAK:
            st.flags[eid].add("privacy")
    elif c in ("Coordinator", "TamperEvidentBag", "BagStrip"):
        if kind not in LEAK:
            st.touched.add(eid)
        elif c == "Coordinator":
            st.disclosed.add(eid)
    elif c == "Plan":
        if kind in LEAK:
            st.privacy = True
        else:
            st.plan_impaired = True


def peers_of_device(S, did, by):
    e = S.ent(did)
    return [d["id"] for d in S.of("SigningDevice")
            if d["id"] != did and d["vendor"] == e["vendor"] and (by == "vendor" or d["model"] == e["model"])]


def apply_impact(S, st, tid, impact, malicious=True):
    on, kind = impact["on"], impact["kind"]
    if on == "self":
        hit(S, st, tid, kind, malicious)
        return
    c = S.cls(tid)
    if on == "protects":
        return
    if on == "loaded_seeds":
        if kind in LEAK:
            st.secret_known.update(S.seeds_on(tid))
        elif kind in ("destroyed", "unavailable"):
            (st.lost if kind == "destroyed" else st.blocked).add(tid)
        return
    if on in ("same_model_devices", "same_vendor_devices"):
        for p in peers_of_device(S, tid, "vendor" if on == "same_vendor_devices" else "model"):
            if kind in LEAK:
                st.secret_known.update(S.seeds_on(p))
            else:
                hit(S, st, p, kind, malicious)
        return
    if on == "wallets":
        for w in S.dependent_wallets(tid):
            if kind in ("tampered", "controlled"):
                st.flags[w].add("tamper" if malicious else "tamper_latent")
            elif kind in LEAK:
                st.flags[w].add("privacy")
            else:
                replaceable = c == "Coordinator" or (c == "Descriptor" and not S.descriptor_is_custom(w))
                st.flags[w].add("soft" if replaceable else "blocked")
        return
    if on == "contents":
        ids = S.contents(tid) if c == "Location" else S.bag_contents(tid)
    elif on == "intrusion_contents":
        ids = S.intrusion_contents(tid)
    elif on == "area_contents":
        ids = S.area_contents(tid)
    elif on == "knowledge":
        ids = S.memory_backups(tid)
    elif on == "access":
        ids = S.reachable_entities(tid)
    elif on == "items":
        ids = [tid]
    else:
        raise ValueError(f"impact selector {on} is not implemented")
    unless = impact.get("unless")
    for i in ids:
        if not (unless and S.holds(i, unless)):
            hit(S, st, i, kind, malicious)


# ---------------------------------------------------------------- owners: availability

class Owner:
    """What a set of people (default: everybody) can obtain. strict: blocked parts count as unavailable too."""

    def __init__(self, S, st, strict, people=None):
        self.S, self.st, self.strict = S, st, strict
        everyone = S.ids_of("Person")
        self.persons = {p for p in (everyone if people is None else people) if self.ok(p)}
        self.reach = set(S.ids_of("Location")) if not everyone else set().union(*[S.reach(p) for p in self.persons]) if self.persons else set()
        self._cache = {}

    def ok(self, eid):
        return eid not in self.st.lost and not (self.strict and eid in self.st.blocked)

    def reachable(self, eid):
        return self.ok(eid) and self.S.loc_of(eid) in self.reach

    def coordinator_usable(self, cid, seen):
        co = self.S.ent(cid)
        return self.reachable(co["runs_on"]) and (not co.get("password") or self.obtain(co["password"], seen))

    def obtain(self, sid, seen=frozenset()):
        S, st = self.S, self.st
        if sid in st.secret_lost or sid in st.tampered or not self.ok(sid) or (self.strict and sid in st.secret_blocked):
            return False
        if sid in seen:
            return False
        if sid in self._cache and not seen:
            return self._cache[sid]
        seen = seen | {sid}
        res = False
        for bid, item in S.copies(sid):
            if not self.ok(bid) or bid in st.tampered:
                continue
            if S.ent(bid)["medium"] == "memory":
                if any(p in self.persons for p in S.memory_holders(bid)):
                    res = True
                    break
            elif S.loc_of(bid) in self.reach and self.decryptable(item, seen):
                res = True
                break
        if not res and S.cls(sid) == "Seed":
            res = any(self.device_usable(d, seen) for d in S.ent(sid).get("devices", []))
        if not res and S.cls(sid) == "Descriptor":
            res = any(self.device_usable(d, seen) for d in S.devices_storing(sid)) or any(self.coordinator_usable(c, seen) for c in S.coordinators_storing(sid))
        if not seen - {sid}:
            self._cache[sid] = res
        return res

    def device_usable(self, did, seen):
        pin = self.S.ent(did).get("pin")
        return self.reachable(did) and (not pin or self.obtain(pin, seen))

    def decryptable(self, item, seen):
        enc = item.get("encrypted_with")
        if not enc:
            return True
        return any(self.obtain(next(iter(alt.values())), seen) for alt in enc)

    def signer_ok(self, sg):
        return self.obtain(sg["seed"]) and ("passphrase" not in sg or self.obtain(sg["passphrase"]))

    def descriptor_copy(self, wid):
        """A stored copy can be obtained: a backup item, or a registration on a usable signing device."""
        d = self.S.ent(wid).get("descriptor")
        return bool(d) and self.obtain(d)

    def descriptor_ok(self, wid):
        """The descriptor is available as a copy, or, if it is a default one, can be rebuilt from the keys of
        all signers of all policies. A single-sig wallet needs nothing extra: its one signer is needed anyway."""
        if self.descriptor_copy(wid):
            return True
        return not self.S.descriptor_is_custom(wid) and all(self.signer_ok(sg) for _, _, sg in self.S.signers(wid))

    def counts(self, wid):
        return tuple(sum(self.signer_ok(sg) for sg in p["signers"]) for p in self.S.ent(wid)["spending_policies"])

    def profile(self, wid):
        """Signers per policy and whether a descriptor copy exists (only where the keys do not give the descriptor): what redundancy is left."""
        return self.counts(wid) + (int(self.S.needs_registration(wid) and self.descriptor_copy(wid)),)


def tier(S, st, wid):
    """0 usable now, 1 temporary lock-out (delay, unavailable parts), 2 permanent loss."""
    pols = S.ent(wid)["spending_policies"]
    strict, relaxed = Owner(S, st, True), Owner(S, st, False)

    def enough(owner):
        return [c >= p["threshold"] for c, p in zip(owner.counts(wid), pols)]

    if strict.descriptor_ok(wid):
        es = enough(strict)
        if any(e and p.get("delay_blocks", 0) == 0 for e, p in zip(es, pols)):
            return 0
        if any(es):
            return 1
    if relaxed.descriptor_ok(wid) and any(enough(relaxed)):
        return 1
    return 2


# ---------------------------------------------------------------- attacker

def attacker_secrets(S, st):
    known = set(st.secret_known)
    while True:
        n = len(known)
        for d in st.controlled:
            known.update(S.seeds_on(d))
            for co in S.coordinators_on(d):
                known.update(S.ent(co).get("stores_descriptors", []))
        for e in st.disclosed:
            if is_a(S.cls(e), "Device"):
                pin = S.ent(e).get("pin")
                if not pin or pin in known:
                    known.update(S.seeds_on(e))
                    known.update(S.ent(e).get("stores_descriptors", []))
                for co in S.coordinators_on(e):
                    if not S.ent(co).get("password") or S.ent(co)["password"] in known:
                        known.update(S.ent(co).get("stores_descriptors", []))
            elif S.cls(e) == "Coordinator":
                known.update(S.ent(e).get("stores_descriptors", []))
            elif S.cls(e) == "Backup":
                for item in S.ent(e)["items"]:
                    enc = item.get("encrypted_with")
                    if not enc or any(next(iter(alt.values())) in known for alt in enc):
                        known.update(v for k, v in item["subject"].items() if k != "plan")
                        if "plan" in item["subject"]:
                            known.add(PLAN)
        if len(known) == n:
            return known


def compromised_counts(S, wid, known):
    return tuple(sum(sg["seed"] in known and ("passphrase" not in sg or sg["passphrase"] in known) for sg in p["signers"])
                 for p in S.ent(wid)["spending_policies"])


def theft(S, st, wid, known):
    pols = S.ent(wid)["spending_policies"]
    return any(c >= p["threshold"] for c, p in zip(compromised_counts(S, wid, known), pols))


def theft_delay(S, wid, known):
    """Least delay of a policy that the attacker's keys satisfy, None if there is none."""
    met = [p["delay_blocks"] for c, p in zip(compromised_counts(S, wid, known), S.ent(wid)["spending_policies"]) if c >= p["threshold"]]
    return min(met, default=None)


def theft_kind(S, wid, known):
    """immediate if a policy without delay is met, after_delay if only delayed policies are, else None."""
    d = theft_delay(S, wid, known)
    return None if d is None else "immediate" if d == 0 else "after_delay"


def spend_delay(owner, wid):
    """Least delay of a policy the people of `owner` can satisfy, INF if they cannot spend the wallet."""
    if not owner.descriptor_ok(wid):
        return INF
    pols = owner.S.ent(wid)["spending_policies"]
    return min((p["delay_blocks"] for p in pols if sum(owner.signer_ok(sg) for sg in p["signers"]) >= p["threshold"]), default=INF)


def tampered_dependency(S, st, wid):
    """A tampered backup of a seed or descriptor the wallet depends on."""
    deps = S.deps(wid)
    for bid in st.tampered:
        if S.cls(bid) == "Backup" and any(v in deps for item in S.ent(bid)["items"] for k, v in item["subject"].items() if k != "plan"):
            return True
    return bool(st.tampered & deps & set(S.ids_of("Descriptor")))


# ---------------------------------------------------------------- outcomes

class Evaluator:
    def __init__(self, S):
        self.S = S
        empty = State()
        self.base_counts = {w: Owner(S, empty, True).profile(w) for w in S.ids_of("Wallet")}
        self.base_tier = {w: tier(S, empty, w) for w in S.ids_of("Wallet")}
        self.atoms = self._atoms()
        self.baseline = self.baseline_warnings()

    def _atoms(self):
        S, atoms = self.S, []
        for p in S.ids_of("Person"):
            atoms.append((p, lambda st, p=p: hit(S, st, p, "destroyed"),
                          lambda st, p=p: [apply_impact(S, st, p, {"on": o, "kind": "disclosed"}) for o in ("access", "knowledge")]))
        for l in S.ids_of("Location"):
            atoms.append((l, lambda st, l=l: apply_impact(S, st, l, {"on": "contents", "kind": "destroyed"}),
                          lambda st, l=l: apply_impact(S, st, l, {"on": "contents", "kind": "disclosed"})))
        for d in S.ids_of("Device"):
            atoms.append((d, lambda st, d=d: hit(S, st, d, "destroyed"),
                          lambda st, d=d: apply_impact(S, st, d, {"on": "loaded_seeds", "kind": "disclosed"})))
        for b in S.ids_of("Backup"):
            atoms.append((b, lambda st, b=b: hit(S, st, b, "destroyed"), lambda st, b=b: hit(S, st, b, "disclosed")))
        for s in [e for c in CREDENTIALS for e in S.ids_of(c)]:
            atoms.append((s, lambda st, s=s: hit(S, st, s, "destroyed"), lambda st, s=s: hit(S, st, s, "disclosed")))
        return atoms

    def margin_left(self, st, wid):
        """True if no single further failure or compromise makes the wallet unusable or stolen."""
        S = self.S
        t0 = tier(S, st, wid)
        if t0 != 0:
            return False
        for _, lose, leak in self.atoms:
            s2 = st.copy()
            lose(s2)
            if tier(S, s2, wid) > t0:
                return False
            s3 = st.copy()
            leak(s3)
            if theft(S, s3, wid, attacker_secrets(S, s3)):
                return False
        return True

    def right_states(self, st):
        """{(people, wallet): ok | delayed | lost} for the rights whose people are all still there; the others are void."""
        S, owners, out = self.S, {}, {}

        def owner(people, strict):
            if (people, strict) not in owners:
                owners[(people, strict)] = Owner(S, st, strict, people)
            return owners[(people, strict)]
        for r in S.rights():
            if r["people"] & st.lost:
                continue
            now = spend_delay(owner(r["people"], True), r["wallet"])
            if now <= r["after"]:
                state = "ok"
            elif now < INF or spend_delay(owner(r["people"], False), r["wallet"]) < INF:
                state = "delayed"
            else:
                state = "lost"
            out[(r["people"], r["wallet"])] = state
        return out

    def access(self, st):
        """[{person, wallet, result}] for every person who is still there and may spend a wallet: ok, delayed (later than
        their earliest right, or only after a repair) or lost (no way left)."""
        states, out = self.right_states(st), []
        for w in sorted({r["wallet"] for r in self.S.rights()}):
            live = [(r, states[(r["people"], w)]) for r in self.S.rights() if r["wallet"] == w and (r["people"], w) in states]
            for p in sorted({p for r, _ in live for p in r["people"]}):
                mine = [(r["after"], s) for r, s in live if p in r["people"]]
                best = min((a for a, s in mine if s == "ok"), default=None)
                result = ("ok" if best == min(a for a, _ in mine) else "delayed") if best is not None else \
                         "delayed" if any(s == "delayed" for _, s in mine) else "lost"
                out.append({"person": p, "wallet": w, "result": result})
        return out

    def within_rights(self, st, wid, delay):
        """The persons who act themselves have a right to spend the wallet at that delay."""
        return bool(st.actors) and any(r["wallet"] == wid and r["people"] <= st.actors and r["after"] <= delay for r in self.S.rights())

    def entitled(self, st, wid):
        return bool(st.actors) and all(any(p in r["people"] and r["wallet"] == wid for r in self.S.rights()) for p in st.actors)

    def rights_report(self):
        """The intended rights against what the intact setup delivers: `rights` (state ok, later, never or earlier than intended)
        and `extra` (people who can spend a main wallet without having the right, alone or in twos)."""
        S, empty = self.S, State()
        rights, extra = [], []
        for r in S.rights():
            got = spend_delay(Owner(S, empty, True, r["people"]), r["wallet"])
            state = "ok" if got == r["after"] else "never" if got == INF else "later" if got > r["after"] else "earlier"
            rights.append({"people": sorted(r["people"]), "wallet": r["wallet"], "after": r["after"], "got": None if got == INF else got, "state": state})
        mains, people, flagged = [w for w in S.ids_of("Wallet") if S.is_main(w)], S.ids_of("Person"), set()
        for n in (1, 2):
            for q in map(frozenset, combinations(people, n)):
                for w in mains:
                    allowed = min((r["after"] for r in S.rights() if r["wallet"] == w and r["people"] <= q), default=INF)
                    got = spend_delay(Owner(S, empty, True, q), w)
                    if got < allowed and not any((p, w) in flagged for p in q):
                        flagged.add((q, w) if n > 1 else (next(iter(q)), w))
                        extra.append({"people": sorted(q), "wallet": w, "got": got})
        return {"rights": rights, "extra": extra}

    def baseline_warnings(self):
        """Where the intact setup does not give the people the access they should have, or gives more."""
        S, out = self.S, []
        name = lambda ids: " and ".join(S.ent(i).get("name", i) for i in sorted(ids))
        when = lambda b: "at once" if b == 0 else f"after {b} blocks (about {round(b / 144)} days)"
        report = self.rights_report()
        for r in report["rights"]:
            if r["state"] in ("later", "never"):
                out.append(f"rights: {name(r['people'])} should be able to spend {name([r['wallet']])} {when(r['after'])} but " + ("cannot at all" if r["got"] is None else f"only can {when(r['got'])}"))
            elif r["state"] == "earlier":
                out.append(f"rights: {name(r['people'])} can spend {name([r['wallet']])} {when(r['got'])}, earlier than intended ({when(r['after'])})")
        for e in report["extra"]:
            out.append(f"rights: {name(e['people'])} can spend {name([e['wallet']])} {when(e['got'])} without having that right")
        return out

    def evaluate(self, st, access=None):
        S, out = self.S, []
        known = attacker_secrets(S, st)
        access = self.access(st) if access is None else access
        affected = st.touched | st.lost | st.blocked | st.disclosed | st.controlled | st.tampered | st.secret_lost | st.secret_blocked | st.secret_known
        for w in S.ids_of("Wallet"):
            main = S.is_main(w)
            loss = "main_loss" if main else "aux_loss"
            flags = st.flags.get(w, set())
            res = []

            def add(outcome, detail, exploit="none"):
                res.append({"wallet": w, "outcome": outcome, "detail": detail, "exploit": exploit})

            delay = theft_delay(S, w, known)
            legit = delay is not None and self.within_rights(st, w, delay)
            if delay is not None and not legit:
                kind = "immediate" if delay == 0 else "after_delay"
                add(loss, "attacker holds enough signers" + (", but only for a policy that opens after its delay" if kind == "after_delay" else ""), kind)
            elif "tamper" in flags:
                add(loss, "transaction or wallet manipulated", "at_use")
            elif "tamper_latent" in flags:
                add(loss, "wallet set up wrongly", "at_recovery")
            elif tampered_dependency(S, st, w):
                add(loss, "tampered backup used at recovery", "at_recovery")
            mine = {a["person"]: a["result"] for a in access if a["wallet"] == w}
            # everybody who may spend it is gone: nobody is left who could be locked out
            nobody = main and not mine and any(r["wallet"] == w for r in S.rights())
            if main and mine:
                owners = {p: r for p, r in mine.items() if S.is_owner(p)}
                gone = [p for p, r in owners.items() if r == "lost"]
                if all(r == "lost" for r in mine.values()):
                    add(loss, "nobody who may spend it can reach it any more")
                elif owners and len(gone) == len(owners):
                    add(loss, "every owner has lost all access")
                else:
                    if gone:
                        add("owner_access_lost", "an owner has lost every way to the funds while another owner keeps one")
                    for p, r in mine.items():
                        if r == "delayed":
                            add("lockout_temporary" if p in owners else "latent_margin", "access only later than intended, or after a repair")
                        elif r == "lost" and p not in owners:
                            add("latent_no_margin", "a person who may spend it has lost every way to it")
            elif not nobody:
                t = tier(S, st, w)
                if t == 2:
                    add(loss, "no usable policy remains")
                elif t == 1:
                    add("lockout_temporary" if main else "inconvenience", "usable only after a delay, repair or reconstruction")
            if "blocked" in flags:
                add("lockout_temporary" if main else "inconvenience", "wallet blocked by the threat")
            if "privacy" in flags or st.privacy or (descriptor_known(S, w, known) and not self.entitled(st, w)):
                add("privacy_loss", "holdings or structure become known")
            if "soft" in flags or (S.deps(w) & affected):
                add("inconvenience", "a part must be repaired or replaced")
            if st.plan_impaired:
                add("latent_no_margin", "plan unusable for recovery")
            if not nobody and not any(r["outcome"] in ("main_loss", "aux_loss", "lockout_temporary", "owner_access_lost") for r in res):
                degraded = Owner(S, st, True).profile(w) != self.base_counts[w] or (any(compromised_counts(S, w, known)) and not legit)
                if degraded:
                    margin = self.margin_left(st, w)
                    add("latent_margin" if margin else "latent_no_margin", "fewer independent parts remain" if margin else "one further failure is critical")
            out.extend(res)
        return out
