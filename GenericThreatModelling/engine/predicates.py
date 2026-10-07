"""Named structural predicates of the threat and mechanism catalogs. A predicate returns True, False,
or None when it does not apply to the entity (None is treated as False)."""
from itertools import combinations

from model import PLAN


def has_delayed_policy(S, wid):
    return any(p.get("delay_blocks", 0) > 0 for p in S.ent(wid)["spending_policies"])


def has_encrypted_items(S, bid):
    return any(item.get("encrypted_with") for item in S.ent(bid)["items"])


def supply_chain_direct(S, did):
    chain = S.ent(did).get("supply_chain")
    return bool(chain) and set(chain) <= {"vendor"}


def has_spare_signers(S, wid):
    return any(len(p["signers"]) > p["threshold"] for p in S.ent(wid)["spending_policies"])


def requires_several_signers(S, wid):
    immediate = [p for p in S.ent(wid)["spending_policies"] if p.get("delay_blocks", 0) == 0]
    return bool(immediate) and all(p["threshold"] >= 2 for p in immediate)


def seed_used_with_passphrase(S, sid):
    users = [sg for w in S.ids_of("Wallet") for _, _, sg in S.signers(w) if sg["seed"] == sid]
    return bool(users) and all("passphrase" in sg for sg in users)


def _bag_of_strip(S, stid):
    return next((b for b in S.of("TamperEvidentBag") if b["strip"] == stid), None)


def strip_and_bag_reachable_together(S, stid):
    bag = _bag_of_strip(S, stid)
    if not bag:
        return None
    ls, lb = S.loc_of(stid), S.loc_of(bag["id"])
    if S.root(ls) == S.root(lb):
        return True
    return any(ls in S.reach(p["id"]) and lb in S.reach(p["id"]) for p in S.of("Person"))


def strip_and_bag_stored_apart(S, stid):
    r = strip_and_bag_reachable_together(S, stid)
    return None if r is None else not r


def _completable(S, sg, locs_of):
    """True if the places in `locs_of` let one complete the signer: its seed and its passphrase."""
    seed_ok = bool(locs_of(S.secret_locations(sg["seed"])))
    pass_ok = "passphrase" not in sg or bool(locs_of(S.secret_locations(sg["passphrase"])))
    return seed_ok and pass_ok


def signers_stored_apart(S, wid):
    """No single place and no single person can complete enough signers of one policy."""
    persons = S.of("Person")
    if not any(len(p["signers"]) >= 2 for p in S.ent(wid)["spending_policies"]):
        return None
    for p in S.ent(wid)["spending_policies"]:
        if len(p["signers"]) < 2:
            continue
        roots = {S.root(l) for sg in p["signers"] for l in S.secret_locations(sg["seed"])}
        for root in roots:
            n = sum(_completable(S, sg, lambda ls: {l for l in ls if S.root(l) == root}) for sg in p["signers"])
            if n >= p["threshold"]:
                return False
        for person in persons:
            reach = S.reach(person["id"])
            n = sum(_completable(S, sg, lambda ls: {l for l in ls if l in reach}) for sg in p["signers"])
            if n >= p["threshold"]:
                return False
    return True


def secret_parts_stored_apart(S, sid):
    """A passphrase apart from its seed, a PIN apart from its device."""
    c = S.cls(sid)
    pairs = []
    if c == "Passphrase":
        pairs = [(S.secret_roots(sg["seed"]), S.secret_roots(sid)) for w in S.ids_of("Wallet") for _, _, sg in S.signers(w) if sg.get("passphrase") == sid]
    elif c == "Seed":
        pairs = [(S.secret_roots(sid), S.secret_roots(sg["passphrase"])) for w in S.ids_of("Wallet") for _, _, sg in S.signers(w) if sg["seed"] == sid and "passphrase" in sg]
    elif c == "PinPassword":
        pairs = [({S.root(S.loc_of(d["id"]))}, S.secret_roots(sid)) for d in S.of("Device") if d.get("pin") == sid]
    if not pairs:
        return None
    return all(not (a & b) for a, b in pairs)


def has_copies_in_different_locations(S, sid):
    roots = {S.root(S.loc_of(b)) for b, _ in S.copies(sid)}
    return len(roots) >= 2


def wallet_descriptors_registered(S, did):
    """The device can register descriptors and has that of every wallet it signs for that it cannot derive alone."""
    wallets = S.registration_wallets(did)
    if not wallets:
        return None
    if S.registration_support(did) != "registers":
        return False
    stored = S.ent(did).get("stores_descriptors", [])
    return all(S.ent(w).get("descriptor") in stored for w in wallets)


def descriptor_at_device_location(S, did):
    """Every descriptor the device needs has a copy in the same place as the device, so it can be loaded when signing."""
    wallets = S.registration_wallets(did)
    if not wallets:
        return None
    here = S.root(S.loc_of(did))
    return all(S.ent(w).get("descriptor") and here in S.secret_roots(S.ent(w)["descriptor"]) for w in wallets)


def quorum_needs_travel(S, pid):
    """The least journey to a group of signers that can spend at once reaches the first row of the travel table."""
    return S.quorum_minutes(pid) >= S.cat.ratings["protection"]["travel_minutes"][0]["at_least"]


REGISTRY = {f.__name__: f for f in (
    has_delayed_policy, has_encrypted_items, supply_chain_direct, has_spare_signers, requires_several_signers,
    seed_used_with_passphrase, strip_and_bag_reachable_together, strip_and_bag_stored_apart, signers_stored_apart,
    secret_parts_stored_apart, has_copies_in_different_locations, wallet_descriptors_registered,
    descriptor_at_device_location, quorum_needs_travel,
)}


def holds(S, predicate, eid):
    return bool(REGISTRY[predicate["name"]](S, eid))


def linking_descriptor(S, wid, known):
    """The attacker knows a descriptor of another wallet that contains a key of this wallet, or the plan."""
    if PLAN in known:
        return True
    mine = {(sg["seed"], sg.get("passphrase")) for _, _, sg in S.signers(wid)}
    for w in S.ids_of("Wallet"):
        d = S.ent(w).get("descriptor")
        if w != wid and d in known and mine & {(sg["seed"], sg.get("passphrase")) for _, _, sg in S.signers(w)}:
            return True
    return False


KNOWLEDGE = {"linking_descriptor": linking_descriptor}
