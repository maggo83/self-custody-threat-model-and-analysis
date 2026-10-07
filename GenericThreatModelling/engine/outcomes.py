"""Outcomes of a state: the rights of the people against what the setup still delivers, what the attacker can do,
and the facts from which the outcome rules of Ratings.json derive the outcomes per wallet."""
from itertools import combinations

import access
from access import State, apply_impact, spend_delay, spend_tree, theft_delay, tier
from graph import INF, evaluate, flag
from ontology import is_a


class Evaluator:
    def __init__(self, S):
        self.S = S
        self.actor, self.asset = S.model["actor"], S.model["asset"]
        self.assets = S.ids_of(self.asset["class"])
        self.rules = S.cat.ratings["outcome_rules"]["rules"]
        self.by_asset = {k: v for k, v in S.cat.ratings["outcome_by_asset"].items() if isinstance(v, list)}
        empty = State()
        self.base_profile = {w: access.profile(spend_tree(S, w), access.people(S, empty, None, True)) for w in self.assets}
        self.base_tier = {w: tier(S, empty, w) for w in self.assets}
        self.main = {w: S.holds(w, self.asset["main_when"]) for w in self.assets}
        self.secret_deps = {w: [e for e in access.deps(S, w) if is_a(S.cls(e), "Secret")] for w in self.assets}
        self.privacy_entities = [e for e, (c, _) in S.by_id.items() if flag(c, "privacy") and not is_a(c, self.asset["class"])]
        self.singletons = [e for e, (c, _) in S.by_id.items() if flag(c, "singleton")]
        self.probes = self._probes()
        self.base_critical = {}
        self.baseline = self.baseline_warnings()

    # ------------------------------------------------------------------ rights
    def is_main(self, wid):
        return self.main[wid]

    def is_owner(self, pid):
        return self.actor["owner_role"] in self.S.ent(pid).get("roles", [])

    def rights(self):
        """Who may spend a wallet after how long: one entry per (set of people, wallet) with the smallest declared delay."""
        if "_rights" in self.__dict__:
            return self._rights
        S, a = self.S, self.actor
        mains = [w for w in self.assets if self.is_main(w)]
        found = {}
        for p in S.of(a["class"]):
            for e in p.get(a["rights"], []):
                people = frozenset([p["id"], *e.get(a["with"], [])])
                for w in e.get(a["assets"], mains):
                    found[(people, w)] = min(found.get((people, w), INF), e.get(a["after"], 0))
        out = [{"people": ppl, "wallet": w, "after": d} for (ppl, w), d in found.items()]
        self._rights = tuple(sorted(out, key=lambda r: (r["wallet"], r["after"], sorted(r["people"]))))
        return self._rights

    def gone(self, st):
        return {p for p in self.S.ids_of(self.actor["class"]) if st.has(p, *access.GONE)}

    def right_states(self, st, affected=None):
        """{(people, wallet): ok | delayed | lost} for the rights whose people are all still there; the others are void.
        A right whose wallet and people the state does not touch keeps its state in the intact setup."""
        S, out, gone = self.S, {}, self.gone(st)
        affected = st.affected() if affected is None else affected
        if "_base_rights" not in self.__dict__:
            self._base_rights = None
            self._base_rights = self.right_states(State())
        for r in self.rights():
            if r["people"] & gone:
                continue
            if self._base_rights is not None and not (access.deps(S, r["wallet"]) & affected) and not st.actors:
                out[(r["people"], r["wallet"])] = self._base_rights[(r["people"], r["wallet"])]
                continue
            now = spend_delay(S, st, r["wallet"], r["people"], True)
            if now <= r["after"]:
                state = "ok"
            elif now < INF or spend_delay(S, st, r["wallet"], r["people"], False) < INF:
                state = "delayed"
            else:
                state = "lost"
            out[(r["people"], r["wallet"])] = state
        return out

    def access(self, st, affected=None):
        """[{person, wallet, result}] for every person who is still there and may spend a wallet: ok, delayed (later than
        their earliest right, or only after a repair) or lost (no way left)."""
        states, out = self.right_states(st, affected), []
        for w in sorted({r["wallet"] for r in self.rights()}):
            live = [(r, states[(r["people"], w)]) for r in self.rights() if r["wallet"] == w and (r["people"], w) in states]
            for p in sorted({p for r, _ in live for p in r["people"]}):
                mine = [(r["after"], s) for r, s in live if p in r["people"]]
                best = min((a for a, s in mine if s == "ok"), default=None)
                result = ("ok" if best == min(a for a, _ in mine) else "delayed") if best is not None else \
                         "delayed" if any(s == "delayed" for _, s in mine) else "lost"
                out.append({"person": p, "wallet": w, "result": result})
        return out

    def within_rights(self, st, wid, delay):
        """The persons who act themselves have a right to spend the wallet at that delay."""
        return bool(st.actors) and any(r["wallet"] == wid and r["people"] <= st.actors and r["after"] <= delay for r in self.rights())

    def entitled(self, st, wid):
        return bool(st.actors) and all(any(p in r["people"] and r["wallet"] == wid for r in self.rights()) for p in st.actors)

    def rights_report(self):
        """The intended rights against what the intact setup delivers: `rights` (state ok, later, never or earlier than intended)
        and `extra` (people who can spend a main wallet without having the right, alone or in twos)."""
        S, empty = self.S, State()
        rights, extra = [], []
        for r in self.rights():
            got = spend_delay(S, empty, r["wallet"], r["people"], True)
            state = "ok" if got == r["after"] else "never" if got == INF else "later" if got > r["after"] else "earlier"
            rights.append({"people": sorted(r["people"]), "wallet": r["wallet"], "after": r["after"], "got": None if got == INF else got, "state": state})
        mains, people, flagged = [w for w in self.assets if self.is_main(w)], S.ids_of(self.actor["class"]), set()
        for n in (1, 2):
            for q in map(frozenset, combinations(people, n)):
                for w in mains:
                    allowed = min((r["after"] for r in self.rights() if r["wallet"] == w and r["people"] <= q), default=INF)
                    got = spend_delay(S, empty, w, q, True)
                    if got < allowed and not any((p, w) in flagged for p in q):
                        flagged.add((q, w) if n > 1 else (next(iter(q)), w))
                        extra.append({"people": sorted(q), "wallet": w, "got": got})
        return {"rights": rights, "extra": extra}

    def baseline_warnings(self):
        """Where the intact setup does not give the people the access they should have, or gives more."""
        S, out = self.S, []
        name = lambda ids: " and ".join(S.name(i) for i in sorted(ids))
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

    # ------------------------------------------------------------------ margin
    def _probes(self):
        """(entity, lose, leak, touched): single further failures and leaks from the probes of the access model, each as
        the statuses it sets in an empty state; `touched` is None for a person, whose loss changes who can act."""
        S, out = self.S, []
        actor = self.actor["class"]

        def statuses(e, impacts):
            st = State()
            for impact in impacts:
                apply_impact(S, st, e, impact)
            return {k: frozenset(v) for k, v in st.status.items()}
        for probe in S.model["margin_probes"]:
            for e in S.ids_of(probe["class"]):
                lose, leak = statuses(e, probe["lose"]), statuses(e, probe["leak"])
                touched = None if is_a(S.cls(e), actor) else set(lose) | set(leak)
                out.append((e, lose, leak, touched))
        return out

    @staticmethod
    def _with(st, statuses):
        s2 = st.copy()
        for e, kinds in statuses.items():
            for k in kinds:
                s2.add(e, k)
        return s2

    def critical(self, st, wid):
        """The probes (single further failures or leaks) after which the wallet is unusable or stolen."""
        S = self.S
        deps, out = access.deps(S, wid), set()
        for e, lose, leak, touched in self.probes:
            if touched is not None and not touched & deps:
                continue
            if tier(S, self._with(st, lose), wid) > 0:
                out.add((e, "lose"))
            if theft_delay(S, self._with(st, leak), wid) is not None:
                out.add((e, "leak"))
        return out

    def margin_left(self, st, wid):
        """True if no single further failure or leak makes the wallet unusable or stolen that did not already do so in
        the intact setup: the fault has not used up a margin the setup had."""
        S = self.S
        if tier(S, st, wid) != 0:
            return False
        if wid not in self.base_critical:
            self.base_critical[wid] = self.critical(State(), wid)
        base, deps = self.base_critical[wid], access.deps(S, wid)
        for e, lose, leak, touched in self.probes:
            if touched is not None and not touched & deps:
                continue
            if (e, "lose") not in base and tier(S, self._with(st, lose), wid) > 0:
                return False
            if (e, "leak") not in base and theft_delay(S, self._with(st, leak), wid) is not None:
                return False
        return True

    # ------------------------------------------------------------------ facts and outcomes
    def facts(self, st, wid, access_rows, known_privacy, known):
        S = self.S
        main = self.main[wid]
        deps = access.deps(S, wid) - {wid}
        affected = st.affected()
        mine = {a["person"]: a["result"] for a in access_rows if a["wallet"] == wid}
        owners = {p: r for p, r in mine.items() if self.is_owner(p)}
        has_rights = any(r["wallet"] == wid for r in self.rights())
        touched = bool((deps | {wid}) & affected) or bool(st.actors) or bool(self.gone(st))
        delay = theft_delay(S, st, wid) if touched else None
        legit = delay is not None and self.within_rights(st, wid, delay)
        t = tier(S, st, wid) if touched else self.base_tier[wid]
        f = {
            "main": main,
            "stolen": delay is not None and not legit,
            "theft_immediate": delay == 0,
            "theft_after_delay": delay is not None and delay > 0,
            "theft_legit": legit,
            "wallet_tampered": st.has(wid, "tampered", "controlled"),
            "wallet_faulty": st.has(wid, "faulty"),
            "wallet_unavailable": st.has(wid, "unavailable", "destroyed"),
            "dependency_tampered": any(st.has(e, "tampered") and not flag(S.cls(e), "active") for e in deps & affected),
            "main_with_rightholders": main and bool(mine),
            "nobody_left": main and not mine and has_rights,
            "all_lost": bool(mine) and all(r == "lost" for r in mine.values()),
            "all_owners_lost": bool(owners) and all(r == "lost" for r in owners.values()),
            "some_owner_lost": any(r == "lost" for r in owners.values()),
            "owner_delayed": any(r == "delayed" for r in owners.values()),
            "other_delayed": any(r == "delayed" for p, r in mine.items() if p not in owners),
            "other_lost": any(r == "lost" for p, r in mine.items() if p not in owners),
            "unusable": t == 2,
            "usable_later": t == 1,
            "privacy": known_privacy or st.has(wid, "disclosed") or (touched and access.descriptor_known(S, st, wid) and not self.entitled(st, wid)),
            "deps_affected": bool(deps & affected),
            "plan_impaired": any(st.has(e, "faulty", "unavailable", "destroyed", "tampered") for e in self.singletons),
        }
        degraded = touched and (access.profile(spend_tree(S, wid), access.people(S, st, None, True)) != self.base_profile[wid] or
                                (not legit and any(e in known for e in self.secret_deps[wid])))
        f["degraded"] = degraded
        f["margin"] = self.margin_left(st, wid) if degraded else True
        return f

    def evaluate(self, st, access_rows=None, known=None):
        """Outcomes per wallet in the state; `known` is what the attacker can obtain (computed if not given)."""
        S, out = self.S, []
        affected = st.affected()
        access_rows = self.access(st, affected) if access_rows is None else access_rows
        known = access.attacker_secrets(S, st) if known is None else known
        known_privacy = any(st.has(e, "disclosed") for e in self.privacy_entities)
        for w in self.assets:
            f = self.facts(st, w, access_rows, known_privacy, known)
            emitted = set()
            for rule in self.rules:
                if set(rule.get("unless_emitted", [])) & emitted:
                    continue
                if not evaluate(S, rule["when"], {"@facts": f, "$self": w}):
                    continue
                name = rule["outcome"]
                if name in self.by_asset:
                    name = self.by_asset[name][0 if f["main"] else 1]
                emitted.add(name)
                out.append({"wallet": w, "outcome": name, "detail": rule["detail"], "exploit": rule.get("exploit", "none")})
        return out
