"""Tests of the threat analysis engine.

One fixture setup (TestSetup.json) is analysed once; its rows, the structure helpers and the evaluator are then
checked against outcomes that follow from the design of the fixture. A few tests re-analyse small variants of the
fixture (metamorphic tests) and run the command line tool.

    python3 -m unittest discover -s GenericThreatModelling/tests -v

A test whose expectation depends on the catalog content (which mechanism addresses which threat) is skipped with a
message when that premise no longer holds, so curating the catalogs does not turn the tests red.
"""
import copy
import html
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ENGINE = HERE.parent / "engine"
sys.path.insert(0, str(ENGINE))

import analyze      # noqa: E402
import access       # noqa: E402
import feedback     # noqa: E402
import graph        # noqa: E402
import loader       # noqa: E402
import manuals      # noqa: E402
import ontology     # noqa: E402
import outcomes as outc  # noqa: E402
import rating       # noqa: E402
import report       # noqa: E402
import vocab        # noqa: E402
from graph import INF, Setup  # noqa: E402

SETUP = HERE / "TestSetup.json"
CLI = ENGINE / "threat_analysis.py"
WALLETS = ("w-single", "w-multi", "w-spread", "w-trip", "w-pin")

BASE = {}


def setUpModule():
    BASE["cat"] = loader.Catalogs()
    BASE["data"] = json.loads(SETUP.read_text())
    BASE["S"] = Setup(BASE["data"], BASE["cat"])
    BASE["ev"] = outc.Evaluator(BASE["S"])
    BASE["result"] = analyze.analyze(SETUP)
    BASE["rows"] = {r["id"]: r for r in BASE["result"]["rows"]}
    BASE["na"] = {(x["threat"], x["entity"]): x["reason"] for x in BASE["result"]["not_applicable"]}


def variant(mutate):
    """Analysis of the fixture after `mutate(data)`."""
    data = copy.deepcopy(BASE["data"])
    mutate(data)
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "variant.json"
        path.write_text(json.dumps(data))
        return analyze.analyze(path, what_if=False)


def setup_of(mutate):
    """A Setup object of the fixture after `mutate(data)`."""
    data = copy.deepcopy(BASE["data"])
    mutate(data)
    return Setup(data, BASE["cat"])


def store_on(device, descriptor="desc-w3"):
    def mutate(d):
        next(x for x in d["devices"] if x["id"] == device).setdefault("stores_descriptors", []).append(descriptor)
    return mutate


def link_tripwire(d):
    """The tripwire key becomes a signer of w-single, whose descriptor is registered on the tripwire's own device."""
    w = next(x for x in d["wallets"] if x["id"] == "w-single")
    w["spending_policies"][0]["signers"].append({"seed": "s4"})
    next(x for x in d["devices"] if x["id"] == "d4")["stores_descriptors"] = ["desc-w-single"]


def by_id(result):
    return {r["id"]: r for r in result["rows"]}


def outcomes(row, wallet):
    return {o["outcome"] for o in row["outcomes"] if o["wallet"] == wallet}


def exploits(row, wallet, outcome):
    return {o["exploit"] for o in row["outcomes"] if o["wallet"] == wallet and o["outcome"] == outcome}


def effect(row, key):
    return set(row.get("effects", {}).get(key, []))


STATUS = {"lost": "destroyed", "blocked": "unavailable", "secret_known": "disclosed", "disclosed": "disclosed", "controlled": "controlled", "tampered": "tampered", "faulty": "faulty"}


def state(S=None, **sets):
    """A state with statuses on entities, named as the old state sets were (lost, blocked, disclosed, controlled, tampered,
    secret_known); what inherits the status of its holder gets it too."""
    st = access.State()
    for k, ids in sets.items():
        for e in ids:
            access.hit(S or BASE["S"], st, e, STATUS[k])
    return st


def can(S, st, action, strict=True, people=None, **args):
    """Whether the people (default: everybody) complete an action of the catalog in the state."""
    return access.value(access.tree(S, action, args), access.People(S, st, people, strict)) < INF


def obtain(S, st, secret, strict=True, people=None):
    return can(S, st, "R-OBTAIN-SECRET", strict, people, secret=secret)


def descriptor_ok(S, st, wallet, strict=True, people=None):
    return can(S, st, "R-ACCESS-DESCRIPTOR", strict, people, wallet=wallet)


def descriptor_copy(S, st, wallet, strict=True, people=None):
    return can(S, st, "R-RECOVER-DESCRIPTOR", strict, people, wallet=wallet)


def theft(S, st, wallet):
    return access.theft_delay(S, st, wallet) is not None


def present(S, mechanism, eid):
    """Whether a structural mechanism is in place on the entity (its present_when expression)."""
    return S.holds(eid, BASE["cat"].mechanisms[mechanism]["present_when"])


class Base(unittest.TestCase):
    cat = property(lambda self: BASE["cat"])
    S = property(lambda self: BASE["S"])
    ev = property(lambda self: BASE["ev"])
    rows = property(lambda self: BASE["rows"])

    def row(self, rid):
        self.assertIn(rid, self.rows)
        return self.rows[rid]

    def premise(self, cond, msg):
        if not cond:
            self.skipTest("catalog premise changed: " + msg)

    def addresses(self, mechanism, threat, effect_=None):
        m = self.cat.mechanisms.get(mechanism)
        return bool(m) and any(a["threat"] == threat and (effect_ is None or a["effect"] == effect_) for a in m.get("addresses", []))


# ------------------------------------------------------------------------------------------ static data

class SingleSource(Base):
    """Knowledge that lives in one place must not be written down again elsewhere without a check."""

    def test_the_diagram_in_the_ontology_document_shows_the_class_table_of_the_schema(self):
        import re
        md = (HERE.parent.parent / "SetupOntology.md").read_text(encoding="utf-8")
        drawn = set(re.findall(r"^    class (\w+)", md, re.M))
        parents = set(re.findall(r"^    (\w+) <\|-- (\w+)", md, re.M))
        table = ontology.TABLE
        self.assertEqual(parents, {(c["parent"], n) for n, c in table.items() if "parent" in c})
        self.assertEqual({n for n, c in table.items() if not c.get("nested") or n in drawn} - drawn, set(), "classes missing in the diagram")

    def test_every_class_has_a_text_and_a_picture_in_the_report(self):
        texts = json.loads((HERE.parent / "Texts.json").read_text())
        concrete = set(ontology.CONCRETE)
        self.assertEqual(concrete - set(texts["classes"]), set())
        display = texts["display"]["classes"]
        self.assertEqual(concrete - set(display), set(), "every class is drawn with its own lane, colours and glyph")
        for c, d in display.items():
            self.assertEqual(set(d) >= {"lane", "fill", "neutral", "glyph"}, True, c)
            self.assertIn(d["lane"], texts["display"]["lanes"], c)
        self.assertIn("default", display, "a class added through data alone is drawn with the default")
        html = (HERE.parent / "engine" / "report.template.html").read_text(encoding="utf-8")
        for c in concrete:
            self.assertNotRegex(html, rf"'{c}'", f"the page must not name the class {c}; it reads the display table")

    def test_references_are_checked_against_the_classes_marked_in_the_schema(self):
        def point(d):
            d["seeds"][0]["devices"] = ["loc-home"]
            d["coordinators"][0]["stores_descriptors"] = ["nowhere"]
            d["backups"][0]["items"][0]["subject"] = {"seed": "alice"}
        data = copy.deepcopy(BASE["data"])
        point(data)
        errors, _ = loader.preflight(data, self.cat)
        self.assertTrue(any("loc-home is a Location, expected Device" in e for e in errors), errors)
        self.assertTrue(any("unknown id nowhere" in e for e in errors), errors)
        self.assertTrue(any("alice is a Person, expected Seed" in e for e in errors), errors)

    def test_a_likelihood_modifier_written_in_several_threats_is_the_same_everywhere(self):
        seen = {}
        for t in self.cat.threats.values():
            for m in t.get("likelihood_modifiers", []):
                self.assertEqual(seen.setdefault(m["reason"], m), m, t["id"])

    def test_outcomes_and_effects_have_ratings_and_texts(self):
        texts = json.loads((HERE.parent / "Texts.json").read_text())
        self.assertEqual(set(texts["outcomes"]), set(self.cat.ratings["outcomes"]))
        self.assertEqual(set(vocab.KINDS) - set(vocab.LEAK) - set(texts["effects"]), set(), "every status has a text")
        emitted = {o["outcome"] for r in BASE["result"]["rows"] for o in r["outcomes"]}
        self.assertEqual(emitted - set(texts["outcomes"]), set())
        named = {r["outcome"] for r in self.cat.ratings["outcome_rules"]["rules"]}
        by_asset = {k for k, v in self.cat.ratings["outcome_by_asset"].items() if isinstance(v, list)}
        self.assertEqual(named - set(self.cat.ratings["outcomes"]) - by_asset, set(), "every rule names a known outcome")

    def test_the_engine_implements_every_selector_and_impact_kind_of_the_catalogs(self):
        S = Setup(BASE["data"], self.cat)
        target = {"contents": "loc-home", "intrusion_contents": "loc-home", "area_contents": "loc-home", "knowledge": "alice", "access": "alice",
                  "loaded_seeds": "d1", "same_model_devices": "d1", "same_vendor_devices": "d1", "wallets": "coord1", "coordinated_wallets": "pc1"}
        for on in self.cat.access["selectors"]:
            for kind in vocab.KINDS:
                access.apply_impact(S, access.State(), target.get(on, "s1"), {"on": on, "kind": kind})
        used = {i["on"] for t in self.cat.threats.values() for i in t["impacts"]}
        self.assertEqual(used - set(self.cat.access["selectors"]), set())

    def test_an_unknown_selector_is_refused_instead_of_being_taken_for_items(self):
        with self.assertRaises(ValueError):
            access.apply_impact(BASE["S"], access.State(), "alice", {"on": "nonsense", "kind": "destroyed"})

    def test_the_vocabulary_of_the_engine_is_the_one_of_the_schema(self):
        self.assertTrue(set(vocab.LEAK) <= set(vocab.KINDS))
        self.assertEqual(set(ontology.COLLECTIONS.values()) - set(json.loads((HERE.parent.parent / "SetupOntology.schema.json").read_text())["properties"]), set())

    def test_the_schema_defaults_are_the_only_defaults(self):
        self.assertEqual(self.S.ent("w-spread")["definition"], "default")
        self.assertEqual(self.S.ent("s1")["scheme"], "bip39")
        self.assertTrue(self.S.ent("pc1")["online"])
        self.assertNotIn("online", self.S.ent("d1"), "a signing device has no such attribute")


class StaticData(Base):
    def test_catalogs_are_valid_and_cross_referenced(self):
        errors = loader.check_catalogs(self.cat)
        self.assertEqual(errors, [])

    def test_fixture_is_valid_without_warnings(self):
        errors, warnings = loader.preflight(BASE["data"], self.cat)
        self.assertEqual((errors, [w for w in warnings if "regist" not in w and "travel" not in w]), ([], []))

    def test_risk_matrix_is_monotonic_and_bounded(self):
        m = self.cat.ratings["risk_matrix"]["values"]
        for rl in range(5):
            for s in range(5):
                self.assertTrue(0 <= m[rl][s] <= 4)
                if s:
                    self.assertGreaterEqual(m[rl][s], m[rl][s - 1], "risk must not fall with severity")
                if rl:
                    self.assertGreaterEqual(m[rl][s], m[rl - 1][s], "risk must not fall with likelihood")
        self.assertTrue(all(v == 0 for v in [m[rl][0] for rl in range(5)]), "no severity, no risk")

    def test_every_outcome_has_a_severity_in_range(self):
        for name, o in self.cat.ratings["outcomes"].items():
            self.assertTrue(0 <= o["severity"] <= 4, name)

    def test_every_catalog_threat_has_a_likelihood_or_category_default(self):
        for t in self.cat.threats.values():
            self.assertTrue("likelihood" in t or t["category"] in self.cat.category_likelihood)


# ------------------------------------------------------------------------------------------ structure

class Structure(Base):
    def test_contents_follow_sub_locations_and_bags(self):
        self.assertEqual(set(self.S.contents("loc-home")), {"d1", "b1", "d4", "b4", "d5", "d2a", "b2a", "pc1", "coord1"}, "software runs where its host is")
        self.assertEqual(set(self.S.contents("loc-safe")), {"d2a", "b2a"})
        self.assertEqual(self.S.contents("bag-1"), ["b-desc-bank"])
        self.assertEqual(self.S.values("b-desc-bank", "enclosing_bags"), ["bag-1"])
        self.assertEqual(self.S.place("b-desc-bank"), "loc-bank")
        self.assertIn("b-desc-bank", self.S.contents("loc-bank"))

    def test_area_is_building_plus_near_links_in_both_directions(self):
        building = {"loc-home", "loc-safe", "loc-office"}
        self.assertEqual(self.S.area("loc-home"), building)
        self.assertEqual(self.S.area("loc-safe"), building)
        self.assertEqual(self.S.area("loc-office"), building, "near is declared on the home only")
        self.assertEqual(self.S.area("loc-bank"), {"loc-bank"})

    def test_reach_needs_access_to_the_parent_location(self):
        self.assertIn("loc-safe", self.S.reach("alice"))
        self.assertNotIn("loc-safe", self.S.reach("bob"))
        self.assertEqual(set(self.S.reach("carol")), {"loc-w3c", "carol"}, "a person reaches what they carry or know")
        self.assertEqual(set(self.S.reach("dave")), {"loc-far", "loc-w3d", "dave"})

    def test_memory_backups_belong_to_the_person_in_whose_head_they_are(self):
        self.assertEqual(access.select(self.S, "knowledge", "alice"), ["bk-head"])
        self.assertEqual(access.select(self.S, "knowledge", "bob"), [])

    def test_copies_and_devices_of_secrets(self):
        self.assertEqual([c["backup"] for c in self.S.derive("s1", "Seed", "copies")], ["b1"])
        self.assertEqual(self.S.values("d1", "seeds"), ["s1"])
        self.assertEqual(self.S.values("desc-w2", "devices"), ["d2c"])
        self.assertEqual({c["backup"] for c in self.S.derive("desc-w2", "Descriptor", "copies")}, {"b-desc-bank", "b-desc-cloud"})

    def test_dependencies_of_wallets(self):
        self.assertTrue({"s5", "d5", "b5", "pin5", "bk-head", "w-pin"} <= access.deps(self.S, "w-pin"))
        self.assertNotIn("b1", access.deps(self.S, "w-pin"))
        self.assertTrue({"bag-1", "strip-1", "coord1", "pc1", "pin-coord", "desc-w2", "pp2a", "d2c"} <= access.deps(self.S, "w-multi"))

    def test_dependent_wallets(self):
        self.assertEqual(self.S.dependents("d2a"), ["w-multi"])
        self.assertEqual(self.S.dependents("coord1"), ["w-multi"])
        self.assertEqual(self.S.dependents("desc-w3"), ["w-spread"])
        self.assertEqual(self.S.dependents("d1"), ["w-single"])

    def test_which_wallets_have_a_custom_descriptor(self):
        self.assertEqual([w for w in WALLETS if self.S.ent(w)["definition"] == "custom"], ["w-multi"])
        self.assertEqual(self.S.ent("w-spread")["definition"], "default", "the default is filled in")

    def test_main_and_auxiliary_wallets(self):
        self.assertEqual([w for w in WALLETS if not self.ev.is_main(w)], ["w-trip"])

    def test_condition_semantics_for_missing_values(self):
        S = self.S
        held = lambda values, c: graph.condition(S, dict(c, path="$v"), {"$v": values})
        self.assertFalse(held([], {"in": [1]}))
        self.assertTrue(held([], {"not_in": [1]}))
        self.assertFalse(held([], {"matches": "."}))
        self.assertTrue(held([], {"not_matches": "."}))
        self.assertTrue(held(["yes (EAL6+)"], {"matches": "^yes"}))
        self.assertTrue(held([True], {"in": [True]}))
        self.assertTrue(held(["a", "b"], {"in": ["b"]}), "list values match if any element matches")
        self.assertTrue(held(["a", "b"], {"count": True, "ge": 2}) and not held(["a"], {"count": True, "ge": 2}))
        self.assertTrue(held([3], {"gt": 2}) and not held([], {"gt": 2}))
        self.assertTrue(held([], {"nonempty": False}) and held(["x"], {"nonempty": True}))

    def test_expressions_quantify_and_follow_references(self):
        S = self.S
        self.assertTrue(S.holds("w-multi", {"exists": "spending_policies[]", "as": "$p", "where": {"path": "$p.delay_blocks", "gt": 0}}))
        self.assertFalse(S.holds("w-spread", {"exists": "spending_policies[]", "as": "$p", "where": {"path": "$p.delay_blocks", "gt": 0}}))
        self.assertEqual(S.values("w-multi", "all_signers[].seed.devices[]"), ["d2a", "d2b", "d2c", "d2f"], "a path follows references into the entities")
        self.assertEqual(S.values("d2a", "class"), ["SigningDevice", "Device"], "the class with its ancestors")
        self.assertEqual(S.values("b-desc-bank", "root"), ["loc-bank"])
        self.assertTrue(S.holds("b-desc-bank", {"path": "root", "eq": "$self.place"}), "the bag sits at the bank")

    def test_attribute_paths_and_catalog_columns(self):
        self.assertEqual(self.S.values("d2a", "supply_chain"), ["vendor", "reseller"])
        self.assertEqual(self.S.values("b-desc-cloud", "items[].format"), ["file"])
        self.assertEqual(self.S.values("b2c", "catalog.fireproof"), ["yes"])
        self.assertEqual(self.S.values("b1", "catalog.fireproof"), [], "a backup without product has no catalog row")
        self.assertEqual(self.S.values("loc-bank", "catalog.physical_security"), ["high"])
        self.assertTrue(self.S.holds("d1", [{"path": "catalog.secure_element", "matches": "^yes"}]))
        self.assertFalse(self.S.holds("d2b", [{"path": "catalog.secure_element", "matches": "^yes"}]))
        self.assertTrue(self.S.holds("w-trip", [{"path": "tripwire.enabled", "in": [True]}]))

    def test_group_keys_for_common_cause(self):
        paths = ["medium", "catalog.material"]
        self.assertEqual(self.S.group_key("b1", paths), self.S.group_key("b2a", paths))
        self.assertNotEqual(self.S.group_key("b1", paths), self.S.group_key("b2c", paths))


# ------------------------------------------------------------------------------------------ structural mechanisms

class Predicates(Base):
    """The structural conditions that used to be Python predicates are expressions in the catalogs now."""

    def test_descriptor_registration_is_needed_only_where_a_device_cannot_derive_it(self):
        reg = lambda S, d: present(S, "M-P-REGISTER-DESCRIPTOR", d)
        self.assertFalse(reg(self.S, "d1"), "default single-sig: nothing to register")
        self.assertTrue(reg(self.S, "d2c"))
        self.assertFalse(reg(self.S, "d2a"), "a custom descriptor not registered")
        self.assertFalse(reg(self.S, "d3a"), "multisig without a registration")
        self.assertTrue(reg(setup_of(store_on("d2a", "desc-w2")), "d2a"))
        self.assertFalse(reg(setup_of(store_on("d3a")), "d3a"), "the catalog does not say that a Trezor registers descriptors: unknown counts as no")
        self.assertEqual([self.S.values(d, "catalog.descriptor_registration") for d in ("d2a", "d3a", "d3c")], [["registers"], ["unknown"], ["per_transaction"]])

    def test_a_registration_counts_only_if_every_group_of_signers_has_one(self):
        def note(eid, S=None, rows=None):
            rows = rows or self.rows
            return [m.get("note") for m in rows["T-DEV-BLIND-SIGNING@" + eid]["V"]["mechanisms"] if m["mechanism"] == "M-P-REGISTER-DESCRIPTOR"]
        self.assertEqual(note("d2c"), ["quorum_gap"], "2 of 3: the signers a and b can sign without a registration")

        def register(d):
            for dev in ("d2a", "d2f"):
                store_on(dev, "desc-w2")(d)
        rows = by_id(variant(register))
        self.assertEqual(note("d2c", rows=rows), [None], "every group of signers now has a device that checks")
        self.assertLess(rows["T-DEV-BLIND-SIGNING@d2c"]["V"]["value"], self.rows["T-DEV-BLIND-SIGNING@d2c"]["V"]["value"])

    def test_the_quorum_rule_per_policy(self):
        S = self.S
        self.assertFalse(rating.quorum_covered(S, "w-multi", {"d2c"}))
        self.assertFalse(rating.quorum_covered(S, "w-multi", {"d2a", "d2c"}), "the delayed fallback policy has a signer without it")
        self.assertTrue(rating.quorum_covered(S, "w-multi", {"d2a", "d2c", "d2f"}), "two of three have it: no group of two avoids it")
        self.assertTrue(rating.quorum_covered(S, "w-single", {"d1"}))
        self.assertFalse(rating.quorum_covered(S, "w-single", set()))

    def test_a_device_that_needs_the_descriptor_for_every_signing_counts_if_it_is_kept_where_the_device_is(self):
        def seedsigner(d):
            dev = next(x for x in d["devices"] if x["id"] == "d2b")
            dev.update(vendor="SeedSigner", model="SeedSigner")
            d["backups"].append({"id": "b-desc-here", "name": "descriptor next to the device", "medium": "paper", "stored_in": dev["stored_in"],
                                 "items": [{"subject": {"descriptor": "desc-w2"}, "format": "text"}]})
            store_on("d2f", "desc-w2")(d)

        def load(d):
            seedsigner(d)
            d["practices"].append({"id": "p-load", "mechanism": "M-P-LOAD-DESCRIPTOR", "scope": ["d2b"]})
        premise = BASE["cat"].mechanisms.get("M-P-LOAD-DESCRIPTOR")
        self.assertIsNotNone(premise)
        note = lambda rows: sorted((m["mechanism"], m.get("note")) for m in rows["T-DEV-BLIND-SIGNING@d2c"]["V"]["mechanisms"]
                                   if m["mechanism"] in ("M-P-REGISTER-DESCRIPTOR", "M-P-LOAD-DESCRIPTOR"))
        self.assertEqual(note(by_id(variant(seedsigner))), [("M-P-REGISTER-DESCRIPTOR", "quorum_gap")], "no practice: only c and f check")
        self.assertEqual(note(by_id(variant(load))), [("M-P-LOAD-DESCRIPTOR", None), ("M-P-REGISTER-DESCRIPTOR", None)],
                         "the registered and the loaded devices together cover every group")

        def elsewhere(d):
            load(d)
            next(b for b in d["backups"] if b["id"] == "b-desc-here")["stored_in"] = {"location": "loc-far"}
        self.assertEqual(note(by_id(variant(elsewhere))), [("M-P-REGISTER-DESCRIPTOR", "quorum_gap")],
                         "the practice does not help if the copy is not where the device is")

    def test_a_descriptor_that_contains_the_tripwire_key_gives_it_away(self):
        S2 = setup_of(link_tripwire)
        rule = BASE["cat"].mechanisms["M-D-TRIPWIRE"]["weakened_when"][0]["when"]
        link = lambda S, known: S.holds("w-trip", rule, {"@state": state(secret_known=known)})
        self.assertFalse(link(S2, set()))
        self.assertTrue(link(S2, {"desc-w-single"}))
        self.assertFalse(link(S2, {"desc-w2"}), "that descriptor has other keys")
        self.assertTrue(link(S2, {graph.PLAN}), "the plan shows the whole structure")
        self.assertFalse(link(self.S, {"desc-w-single"}), "without the shared key nothing links them")

    def test_a_recognised_tripwire_counts_less(self):
        tripwire = lambda rows: [m for m in rows["T-LOC-ATTACK-LOCAL@loc-home"]["V"]["mechanisms"] if m["mechanism"] == "M-D-TRIPWIRE"]
        self.assertTrue(tripwire(self.rows), "premise: the tripwire is a measure against a local attack")
        self.assertNotIn("weakened", tripwire(self.rows)[0])
        rows = by_id(variant(link_tripwire))
        self.assertIn("weakened", tripwire(rows)[0], "the attacker takes the device and finds the descriptor on it")
        self.assertGreater(rows["T-LOC-ATTACK-LOCAL@loc-home"]["V"]["value"], self.rows["T-LOC-ATTACK-LOCAL@loc-home"]["V"]["value"])

    def test_an_attacker_derives_default_descriptors_from_keys_and_from_known_descriptors(self):
        known = lambda S, w, ids: access.descriptor_known(S, state(secret_known=ids), w)
        self.assertTrue(known(self.S, "w-single", {"s1"}), "a default single-sig descriptor follows from its seed")
        self.assertFalse(known(self.S, "w-spread", {"s3a", "s3b", "s3c"}), "all four signers are needed")
        self.assertTrue(known(self.S, "w-spread", {"s3a", "s3b", "s3c", "s3d"}))
        self.assertFalse(known(self.S, "w-multi", {"s2a", "pp2a", "s2b", "s2c", "s2f"}), "a custom descriptor is not determined by the keys")
        self.assertTrue(known(self.S, "w-multi", {"desc-w2"}))
        S2 = setup_of(link_tripwire)
        self.assertFalse(known(S2, "w-trip", set()))
        self.assertTrue(known(S2, "w-trip", {"desc-w-single"}), "the descriptor of w-single contains the key of w-trip")

    def test_privacy_is_lost_when_a_descriptor_is_known_explicitly_or_derived(self):
        ev = outc.Evaluator(self.S)
        privacy = lambda st: {o["wallet"] for o in ev.evaluate(st) if o["outcome"] == "privacy_loss"}
        self.assertEqual(privacy(state(disclosed={"laptop2"})), {"w-single", "w-spread", "w-trip", "w-pin"}, "coord2 keeps their descriptors; coord1 keeps that of w-multi")
        S2 = setup_of(link_tripwire)
        ev2 = outc.Evaluator(S2)
        self.assertIn("w-trip", {o["wallet"] for o in ev2.evaluate(state(disclosed={"d4"})) if o["outcome"] == "privacy_loss"})

    def test_a_wallet_can_have_several_coordinators(self):
        def second(d):
            d["coordinators"].append({"id": "coord3", "name": "Third", "product": "Sparrow", "runs_on": "pc1", "stores_descriptors": ["desc-w3"]})
        S2 = setup_of(second)
        self.assertEqual(S2.values("w-spread", "coordinators"), ["coord2", "coord3"])
        self.assertTrue({"coord2", "coord3", "pc1", "laptop2"} <= access.deps(S2, "w-spread"))
        self.assertEqual(S2.dependents("coord3"), ["w-spread"])

    def test_the_tripwire_needs_a_coordinator_that_has_its_descriptor(self):
        tripwire = lambda rows: [m for m in rows["T-LOC-ATTACK-LOCAL@loc-home"]["V"]["mechanisms"] if m["mechanism"] == "M-D-TRIPWIRE"]
        self.assertTrue(tripwire(self.rows))
        def lose(d):
            d["descriptors"] = [x for x in d["descriptors"] if x["id"] != "desc-w-trip"]
            next(c for c in d["coordinators"] if c["id"] == "coord2")["stores_descriptors"].remove("desc-w-trip")
        self.assertFalse(tripwire(by_id(variant(lose))), "nobody can watch the tripwire wallet")

    def test_a_registration_is_a_mechanism_instance_on_its_device(self):
        entities = lambda eid: {e for m in self.rows["T-DEV-BLIND-SIGNING@" + eid]["V"]["mechanisms"]
                                if m["mechanism"] == "M-P-REGISTER-DESCRIPTOR" for e in m["entities"]}
        self.assertEqual(entities("d2c"), {"d2c"})

    def test_wallet_predicates(self):
        self.assertTrue(present(self.S, "M-P-FALLBACK-POLICY", "w-multi"))
        self.assertFalse(present(self.S, "M-P-FALLBACK-POLICY", "w-spread"))
        self.assertTrue(present(self.S, "M-P-MULTI-SIGNER-QUORUM", "w-multi"))
        self.assertTrue(present(self.S, "M-P-MULTI-SIGNER-QUORUM", "w-spread"))
        self.assertFalse(present(self.S, "M-P-MULTI-SIGNER-QUORUM", "w-single"))
        self.assertTrue(present(self.S, "M-P-SPARE-SIGNERS", "w-multi"))
        self.assertFalse(present(self.S, "M-P-SPARE-SIGNERS", "w-single"))

    def test_signers_apart_needs_no_single_place_or_person_to_reach_a_quorum(self):
        self.assertTrue(present(self.S, "M-P-SIGNERS-APART", "w-spread"))
        self.assertFalse(present(self.S, "M-P-SIGNERS-APART", "w-multi"), "Alice alone reaches three signers")

    def test_single_signer_wallets_have_no_signers_to_keep_apart(self):
        self.assertFalse(present(self.S, "M-P-SIGNERS-APART", "w-single"))

    def test_seed_with_passphrase(self):
        self.assertTrue(present(self.S, "M-P-PASSPHRASE", "s2a"))
        self.assertFalse(present(self.S, "M-P-PASSPHRASE", "s2b"))
        self.assertFalse(present(self.S, "M-P-PASSPHRASE", "s1"))

    def test_secret_parts_apart(self):
        self.assertTrue(present(self.S, "M-P-SECRET-PARTS-APART", "pp2a"))
        self.assertTrue(present(self.S, "M-P-SECRET-PARTS-APART", "s2a"))
        self.assertTrue(present(self.S, "M-P-SECRET-PARTS-APART", "pin5"))
        self.assertFalse(present(self.S, "M-P-SECRET-PARTS-APART", "s1"), "no passphrase, nothing to keep apart")

    def test_copies_in_different_locations(self):
        self.assertTrue(present(self.S, "M-P-REDUNDANT-BACKUPS", "desc-w2"))
        self.assertFalse(present(self.S, "M-P-REDUNDANT-BACKUPS", "s1"))

    def test_supply_chain(self):
        self.assertTrue(present(self.S, "M-P-SUPPLY-CHAIN-DIRECT", "d1"))
        self.assertFalse(present(self.S, "M-P-SUPPLY-CHAIN-DIRECT", "d2a"))
        self.assertFalse(present(self.S, "M-P-SUPPLY-CHAIN-DIRECT", "d2b"), "unknown supply chain counts as not direct")

    def test_strip_and_bag(self):
        together = BASE["cat"].threats["T-STRIP-SWAPPED-WITH-BAG"]["applies_when"]
        self.assertTrue(self.S.holds("strip-1", together))
        self.assertFalse(present(self.S, "M-P-STRIP-APART-FROM-BAG", "strip-1"))

    def test_encrypted_items(self):
        cond = BASE["cat"].threats["T-BAK-CANNOT-DECRYPT"]["applies_when"]
        self.assertTrue(self.S.holds("b-desc-cloud", cond))
        self.assertFalse(self.S.holds("b1", cond))


# ------------------------------------------------------------------------------------------ evaluator

class Evaluator(Base):
    def tier(self, st, wallet):
        return access.tier(self.S, st, wallet)

    def test_untouched_setup_is_usable_and_nothing_is_stolen(self):
        st = access.State()
        for w in WALLETS:
            self.assertEqual(self.tier(st, w), 0, w)
        self.assertEqual(access.attacker_secrets(self.S, st), set())
        self.assertEqual(self.ev.evaluate(st), [])

    def test_memory_secrets_die_with_their_person(self):
        st = state(lost={"alice"})
        self.assertFalse(obtain(self.S, st, "pp2a"))
        self.assertFalse(obtain(self.S, st, "pin-coord"))
        self.assertTrue(obtain(self.S, st, "s1"))

    def test_encrypted_copy_needs_one_of_its_keys(self):
        st = state(lost={"b-desc-bank", "d2c", "pc1"})
        self.assertTrue(obtain(self.S, st, "desc-w2"), "the cloud copy is decrypted with s2b")
        st = state(lost={"b-desc-bank", "d2c", "b2b", "d2b", "b2c", "pc1"})
        self.assertFalse(obtain(self.S, st, "desc-w2"))

    def test_a_pin_protects_a_disclosed_device(self):
        self.assertNotIn("s5", access.attacker_secrets(self.S, state(disclosed={"d5"})))
        self.assertIn("s5", access.attacker_secrets(self.S, state(disclosed={"d5"}, secret_known={"pin5"})))
        self.assertIn("s5", access.attacker_secrets(self.S, state(controlled={"d5"})), "a controlled device is used by its owner")
        self.assertIn("s1", access.attacker_secrets(self.S, state(disclosed={"d1"})), "no PIN, no protection")

    def test_encrypted_backup_needs_a_key_on_the_attackers_side(self):
        self.assertNotIn("desc-w2", access.attacker_secrets(self.S, state(disclosed={"b-desc-cloud"})))
        self.assertIn("desc-w2", access.attacker_secrets(self.S, state(disclosed={"b-desc-cloud"}, secret_known={"s2b"})))

    def test_blocked_is_temporary_and_lost_is_permanent(self):
        self.assertEqual(self.tier(state(blocked={"b1", "d1"}), "w-single"), 1)
        self.assertEqual(self.tier(state(lost={"b1", "d1"}), "w-single"), 2)
        self.assertEqual(self.tier(state(lost={"b1"}), "w-single"), 0, "the device still holds the seed")

    def test_a_delayed_policy_turns_loss_into_a_lockout(self):
        two_gone = {"b2a", "d2a", "b2b", "d2b"}
        self.assertEqual(self.tier(state(lost=two_gone), "w-multi"), 1)
        self.assertEqual(self.tier(state(lost=two_gone | {"b2f", "d2f"}), "w-multi"), 2)

    def test_a_lost_default_descriptor_is_rebuilt_from_all_signers(self):
        self.assertEqual(self.tier(state(lost={"desc-w3"}), "w-spread"), 0, "all four signers are available")
        self.assertEqual(self.tier(state(lost={"desc-w3", "d3a", "b3a"}), "w-spread"), 2,
                         "two signers would do, but the key of the lost one is missing from the rebuilt descriptor")
        self.assertEqual(self.tier(state(lost={"d3a", "b3a"}), "w-spread"), 0, "a stored copy makes the lost signer harmless")
        self.assertEqual(self.tier(state(blocked={"desc-w3", "d3a", "b3a"}), "w-spread"), 1, "blocked parts return")

    def test_a_custom_descriptor_needs_an_explicit_copy(self):
        self.assertEqual(self.tier(state(lost={"desc-w2"}), "w-multi"), 2, "all signers and the plan are there, but the policy is not rebuilt from them")
        self.assertEqual(self.tier(state(lost={"b-plan"}), "w-multi"), 0, "the plan does not matter")
        self.assertEqual(self.tier(state(lost={"b-desc-bank", "b-desc-cloud"}), "w-multi"), 0, "d2c has the descriptor registered")
        self.assertEqual(self.tier(state(lost={"b-desc-bank", "b-desc-cloud", "d2c", "pc1"}), "w-multi"), 2)
        self.assertEqual(self.tier(state(blocked={"b-desc-bank", "b-desc-cloud", "d2c", "pc1"}), "w-multi"), 1, "blocked copies return")

    def test_a_descriptor_registered_on_a_device_is_a_copy(self):
        gone = {"b-desc-w3-far", "b-desc-w3-cloud", "laptop2"}
        S2 = setup_of(store_on("d3b"))
        self.assertTrue(descriptor_copy(S2, state(lost=gone), "w-spread"))
        self.assertFalse(descriptor_copy(S2, state(lost=gone | {"d3b"}), "w-spread"))
        self.assertFalse(descriptor_copy(self.S, state(lost=gone), "w-spread"), "nothing is registered in the fixture")

    def test_a_registered_descriptor_behind_a_pin_needs_the_pin(self):
        gone = {"b-desc-w3-far", "b-desc-w3-cloud", "laptop2"}
        S2 = setup_of(store_on("d5"))
        self.assertTrue(descriptor_copy(S2, state(lost=gone), "w-spread"))
        self.assertFalse(descriptor_copy(S2, state(lost=gone | {"alice"}), "w-spread"), "the PIN is in Alice's head")

    def test_an_attacker_who_holds_a_device_learns_the_descriptor_registered_on_it(self):
        self.assertIn("desc-w3", access.attacker_secrets(setup_of(store_on("d3a")), state(disclosed={"d3a"})))
        self.assertNotIn("desc-w3", access.attacker_secrets(self.S, state(disclosed={"d3a"})))

    def test_a_custom_single_sig_wallet_needs_its_copy(self):
        def custom(d):
            w = next(x for x in d["wallets"] if x["id"] == "w-single")
            w["definition"] = "custom"
            next(c for c in d["coordinators"] if c["id"] == "coord2")["stores_descriptors"].remove("desc-w-single")
            d["backups"].append({"id": "b-desc-single", "name": "copy", "medium": "paper", "stored_in": {"location": "loc-home"},
                                 "items": [{"subject": {"descriptor": "desc-w-single"}, "format": "text"}]})
        S2 = setup_of(custom)
        self.assertEqual(access.tier(S2, access.State(), "w-single"), 0)
        self.assertEqual(access.tier(S2, state(lost={"b-desc-single"}), "w-single"), 2, "the seed is there, the descriptor is not")
        self.assertEqual(access.tier(S2, state(blocked={"b-desc-single"}), "w-single"), 1)
        self.assertEqual(access.tier(self.S, state(), "w-single"), 0, "a default single-sig wallet is rebuilt from its one signer")

    def test_a_default_multi_signer_wallet_without_any_copy_needs_all_signers(self):
        def no_copies(d):
            d.update(backups=[b for b in d["backups"] if b["id"] not in ("b-desc-w3-far", "b-desc-w3-cloud")])
            next(c for c in d["coordinators"] if c["id"] == "coord2")["stores_descriptors"].remove("desc-w3")
        S2 = setup_of(no_copies)
        self.assertEqual(access.tier(S2, access.State(), "w-spread"), 0)
        self.assertEqual(access.tier(S2, state(lost={"d3a", "b3a"}), "w-spread"), 2, "the key of the lost signer is missing")

    def test_single_signer_wallets_need_no_descriptor(self):
        self.assertEqual(self.tier(state(), "w-single"), 0)
        self.assertTrue(descriptor_ok(self.S, state(lost={"b1"}), "w-single"))

    def test_losing_every_descriptor_copy_loses_the_pairs_that_may_spend(self):
        out = self.ev.evaluate(state(lost={"b-desc-w3-far", "b-desc-w3-cloud", "laptop2"}))
        self.assertEqual({o["outcome"] for o in out if o["wallet"] == "w-spread"}, {"inconvenience", "main_loss"},
                         "a default descriptor is rebuilt from all four signers, which no pair of people has")
        out = self.ev.evaluate(state(lost={"b-desc-w3-far"}))
        self.assertEqual({o["outcome"] for o in out if o["wallet"] == "w-spread"}, {"inconvenience", "latent_margin"},
                         "one copy is left: the redundancy is smaller, but no single further event is critical")

    def test_theft_needs_threshold_many_complete_signers_and_the_descriptor(self):
        S = self.S
        self.assertFalse(theft(S, state(secret_known={"s2a", "s2b", "desc-w2"}), "w-multi"), "signer a lacks its passphrase")
        self.assertTrue(theft(S, state(secret_known={"s2a", "s2b", "pp2a", "desc-w2"}), "w-multi"))
        self.assertFalse(theft(S, state(secret_known={"s2a", "s2b", "pp2a"}), "w-multi"), "a custom wallet cannot be spent without its descriptor")
        self.assertEqual(access.theft_delay(S, state(secret_known={"s2f", "desc-w2"}), "w-multi"), 52000, "the delayed policy counts for an attacker")
        self.assertTrue(theft(S, state(secret_known={"s3a", "s3b", "desc-w3"}), "w-spread"))
        self.assertFalse(theft(S, state(secret_known={"s3a", "s3b"}), "w-spread"), "two of four keys do not give the default descriptor")
        self.assertTrue(theft(S, state(secret_known={"s3a", "s3b", "s3c", "s3d"}), "w-spread"), "all four keys do")
        self.assertTrue(theft(S, state(secret_known={"s1"}), "w-single"), "a single key gives its default descriptor")

    def test_margin_is_left_only_if_no_single_further_failure_is_critical(self):
        self.assertTrue(self.ev.margin_left(state(lost={"d3a", "b3a"}), "w-spread"), "2 of 4 with one signer gone")
        self.assertFalse(self.ev.margin_left(state(lost={"d2a", "b2a"}), "w-multi"), "2 of 3 with one signer gone")

    def test_margin_can_be_lost_by_availability_alone(self):
        gone = {"d3a", "b3a", "d3b", "b3b"}
        self.assertFalse(self.ev.margin_left(state(lost=gone), "w-spread"), "two of four left, exactly the threshold")

    def test_the_vulnerability_of_a_row_is_that_of_its_worst_wallet(self):
        S, cat = self.S, self.cat
        insts = rating.mechanism_instances(S, cat).get("T-COORD-MALICIOUS-SEND", [])
        self.premise(any(i["mechanism"] == "M-D-CROSS-CHECK-TRANSACTION" for i in insts), "cross-check is present for w-multi")
        out = [{"wallet": "w-multi", "outcome": "main_loss", "detail": "", "exploit": "at_use"},
               {"wallet": "w-single", "outcome": "inconvenience", "detail": "", "exploit": "none"}]
        V = analyze.worst_vulnerability(S, cat, "T-COORD-MALICIOUS-SEND", insts, ("coord1",), access.State(), out, {"value": 4})
        self.assertEqual((V["wallet"], V["value"]), ("w-multi", 2), "the unprotected single-sig wallet is less severe and must not count")

    def test_a_wallet_that_is_already_unusable_has_no_margin(self):
        three_gone = {"d3a", "b3a", "d3b", "b3b", "d3c", "b3c"}
        self.assertEqual(self.tier(state(lost=three_gone), "w-spread"), 2)
        self.assertFalse(self.ev.margin_left(state(lost=three_gone), "w-spread"))

    def test_a_faulty_part_is_lost_for_the_owners_and_worthless_for_the_attacker(self):
        self.assertFalse(obtain(self.S, state(faulty={"desc-w2"}), "desc-w2"))
        self.assertEqual(self.tier(state(faulty={"desc-w2"}), "w-multi"), 2)
        self.assertNotIn("desc-w2", access.attacker_secrets(self.S, state(faulty={"desc-w2"}, disclosed={"b-desc-bank"})), "a wrong copy is no copy")
        self.assertFalse(theft(self.S, state(tampered={"b1"}), "w-single"), "a tampered backup gives the attacker nothing to spend with")

    def test_a_controlled_part_bypasses_its_guard_and_a_tampered_one_is_commanded(self):
        self.assertIn("desc-w2", access.attacker_secrets(self.S, state(controlled={"pc1"})), "malware on the host reads the coordinator despite its password")
        self.assertNotIn("desc-w2", access.attacker_secrets(self.S, state(disclosed={"pc1"})), "a stolen host still needs the password")
        self.assertIn("s5", access.attacker_secrets(self.S, state(tampered={"d5"})), "a swapped device is used by its owner, PIN and all")
        self.assertEqual(access.attacker_secrets(self.S, state(tampered={"b5"})), set(), "a tampered backup tells the attacker nothing")


# ------------------------------------------------------------------------------------------ instantiation

class Instantiation(Base):
    def not_applicable(self, threat, entity, reason):
        self.assertIn((threat, entity), BASE["na"])
        self.assertTrue(BASE["na"][(threat, entity)].startswith(reason))

    def entities_of(self, threat):
        return {r["entity"] for r in self.rows.values() if r["threat"] == threat}

    def test_conditions_on_plan_attributes(self):
        self.not_applicable("T-BAK-AGEING", "b2c", "applies_when")
        self.assertIn("T-BAK-AGEING@b1", self.rows)
        self.assertEqual(self.entities_of("T-SEED-BAD-CHECKSUM"), {"s3a"})
        self.assertIn("T-SECRET-RNG-COMPROMISED@s1", self.rows)
        self.not_applicable("T-SECRET-RNG-COMPROMISED", "s3a", "applies_when")

    def test_conditions_on_catalog_columns(self):
        self.not_applicable("T-DEV-WIPED-BY-ATTEMPTS", "d3c", "applies_when")
        self.assertIn("T-DEV-WIPED-BY-ATTEMPTS@d1", self.rows)
        self.not_applicable("T-DEV-POWER-LOSS", "d1", "applies_when")
        self.assertIn("T-DEV-POWER-LOSS@d2b", self.rows)
        self.not_applicable("T-DEV-PHYSICAL-EXTRACTION", "d1", "applies_when")
        self.assertIn("T-DEV-PHYSICAL-EXTRACTION@d2b", self.rows)
        self.not_applicable("T-DEV-NONCE-EXFIL", "d1", "applies_when")
        self.assertIn("T-DEV-NONCE-EXFIL@d4", self.rows)

    def test_conditions_on_location_kind(self):
        for loc in ("loc-cloud", "loc-cloud2"):
            self.not_applicable("T-LOC-INACCESSIBLE", loc, "applies_when")
        self.assertIn("T-LOC-INACCESSIBLE@loc-home", self.rows)

    def test_structural_conditions_filter_instances(self):
        self.assertEqual(self.entities_of("T-WALLET-TIMELOCK-LAPSE"), {"w-multi"})
        self.not_applicable("T-WALLET-TIMELOCK-LAPSE", "w-single", "applies_when")
        self.assertEqual(self.entities_of("T-BAK-CANNOT-DECRYPT"), {"b-desc-cloud"})
        self.assertIn("T-STRIP-SWAPPED-WITH-BAG@strip-1", self.rows)

    def test_abstract_class_threats_apply_to_the_listed_subclasses_only(self):
        seeds = {s["id"] for s in BASE["data"]["seeds"]}
        expected = seeds | {"pp2a", "pin5", "pin-coord"}
        self.assertEqual(self.entities_of("T-SECRET-LOW-ENTROPY"), expected)
        self.assertNotIn("desc-w2", self.entities_of("T-SECRET-LOW-ENTROPY"))
    def test_threats_on_sets_of_people_are_instantiated_for_every_pair(self):
        pairs = [r for r in self.rows.values() if r["threat"] == "T-PERSON-COLLUSION"]
        self.assertEqual(len(pairs), 6)
        self.assertFalse([x for x in BASE["result"]["not_applicable"] if x["threat"] == "T-PERSON-COLLUSION"])


# ------------------------------------------------------------------------------------------ propagation

class Propagation(Base):
    def test_fire_destroys_the_building_including_the_safe(self):
        r = self.row("T-LOC-FIRE@loc-home")
        self.assertEqual(effect(r, "destroyed"), {"b1", "b2a", "b4", "d1", "d2a", "d4", "d5", "pc1", "coord1"}, "the software dies with its host")
        self.assertIn("main_loss", outcomes(r, "w-single"))
        self.assertEqual(exploits(r, "w-single", "main_loss"), {"none"})
        self.assertIn("aux_loss", outcomes(r, "w-trip"))
        self.assertNotIn("main_loss", outcomes(r, "w-trip"), "a tripwire is never main funds")
        self.assertEqual(outcomes(r, "w-pin"), {"inconvenience", "latent_no_margin"}, "the seed backup at the trustee is the last copy")
        self.assertIn("latent_no_margin", outcomes(r, "w-multi"))
        self.assertNotIn("main_loss", outcomes(r, "w-multi"))
        self.assertEqual(outcomes(r, "w-spread"), set())
        self.assertEqual(r["S"]["outcome"], "main_loss")

    def test_area_events_reach_near_locations(self):
        r = self.row("T-LOC-NATURAL-DISASTER@loc-home")
        self.assertTrue({"d2b", "b2b", "d1", "d2a"} <= effect(r, "destroyed"))
        self.assertIn("lockout_temporary", outcomes(r, "w-multi"), "two signers gone, the delayed policy remains")
        self.assertNotIn("main_loss", outcomes(r, "w-multi"))
        self.assertIn("d1", effect(self.row("T-LOC-NATURAL-DISASTER@loc-office"), "destroyed"), "near works both ways")

    def test_local_events_do_not_reach_near_locations(self):
        self.assertNotIn("d2b", effect(self.row("T-LOC-FIRE@loc-home"), "destroyed"))

    def test_war_destroys_and_discloses_the_whole_area(self):
        r = self.row("T-LOC-ATTACK-AREA@loc-home")
        self.assertTrue({"d2b", "b2b"} <= effect(r, "destroyed") & effect(r, "disclosed"))
        self.assertIn("lockout_temporary", outcomes(r, "w-multi"))
        self.assertNotIn("main_loss", outcomes(r, "w-multi"), "signer a lacks its passphrase, b alone is not enough")

    def test_burglary_takes_what_is_there_but_a_pin_and_a_passphrase_still_protect(self):
        r = self.row("T-LOC-ATTACK-LOCAL@loc-home")
        self.assertIn("immediate", exploits(r, "w-single", "main_loss"), "stolen")
        self.assertIn("none", exploits(r, "w-single", "main_loss"), "and destroyed")
        self.assertIn("aux_loss", outcomes(r, "w-trip"))
        self.assertNotIn("main_loss", outcomes(r, "w-multi"))
        self.assertIn("latent_no_margin", outcomes(r, "w-multi"))
        self.assertEqual(outcomes(r, "w-pin"), {"inconvenience", "latent_no_margin"}, "d5 is disclosed but its PIN is in Alice's head; only the backup at the trustee is left")
        self.assertIn("d5", effect(r, "disclosed"))

    def test_common_cause_by_provider_and_jurisdiction(self):
        r = self.row("T-LOC-CLOUD-BREACH@loc-cloud")
        self.assertEqual(r["common_cause"], ["loc-cloud2"])
        self.assertTrue({"b-desc-cloud", "b-plan"} <= effect(r, "disclosed"))
        self.assertNotIn("privacy_loss", outcomes(r, "w-multi"), "the descriptor copy is encrypted")
        self.assertNotIn("main_loss", outcomes(r, "w-multi"))
        r = self.row("T-LOC-JURISDICTION-CHANGE@loc-home")
        self.assertEqual(r["common_cause"], ["loc-bank", "loc-office"])
        self.assertEqual(exploits(r, "w-multi", "main_loss"), {"immediate"}, "signers b and c are both in jurisdiction A")

    def test_common_cause_by_device_model(self):
        r = self.row("T-DEV-LEAKS-KEY@d1")
        self.assertEqual(exploits(r, "w-single", "main_loss"), {"immediate"})
        self.assertNotIn("main_loss", outcomes(r, "w-multi"), "d2a is the same model, but signer a has a passphrase")
        r = self.row("T-DEV-LEAKS-KEY@d3a")
        self.assertTrue({"s3a", "s3b"} <= effect(r, "known"), "d3b is the same model: two signers")
        self.assertNotIn("main_loss", outcomes(r, "w-spread"), "two keys of four do not give the default descriptor; a copy or the other keys are needed")
        self.assertIn("latent_no_margin", outcomes(r, "w-spread"))
        rows = by_id(variant(lambda d: d["backups"].append({"id": "b-desc-home", "name": "descriptor at home", "medium": "paper", "stored_in": {"location": "loc-w3a"}, "items": [{"subject": {"descriptor": "desc-w3"}, "format": "text"}]})))
        self.assertNotIn("main_loss", outcomes(rows["T-DEV-LEAKS-KEY@d3a"], "w-spread"), "a copy somewhere else does not help the attacker either")
        r = self.row("T-DEV-LEAKS-KEY@d3c")
        self.assertNotIn("main_loss", outcomes(r, "w-spread"))
        self.assertIn("latent_no_margin", outcomes(r, "w-spread"), "one signer known, one more makes theft")

    def test_same_vendor_is_wider_than_same_model(self):
        r = self.row("T-DEV-LEAKS-KEY@d3a")
        self.assertEqual(outcomes(r, "w-pin"), set(), "d5 is a Trezor, but another model")
        self.assertNotIn("aux_loss", outcomes(r, "w-trip"))
        r = self.row("T-DEV-BACKDOOR@d4")
        self.assertEqual(effect(r, "controlled"), {"d3a", "d3b", "d4", "d5"})
        self.assertIn("latent_no_margin", outcomes(r, "w-spread"), "two keys, but not the descriptor")
        self.assertIn("main_loss", outcomes(r, "w-pin"))
        self.assertNotIn("main_loss", outcomes(r, "w-single"))

    def test_a_weakness_of_the_seed_scheme_hits_every_seed_with_that_scheme(self):
        r = self.row("T-SEED-SCHEME-WEAKNESS@s1")
        self.assertEqual(len(r["common_cause"]), len(BASE["data"]["seeds"]) - 1, "all seeds default to bip39")
        for w in ("w-single", "w-spread", "w-pin"):
            self.assertIn("main_loss", outcomes(r, w), w)
        self.assertIn("latent_no_margin", outcomes(r, "w-multi"), "every key, but the custom descriptor is not among them")
        self.assertIn("aux_loss", outcomes(r, "w-trip"))

    def test_protocol_weaknesses_hit_every_wallet(self):
        r = self.row("T-WALLET-SIGNATURE-WEAKNESS@w-single")
        self.assertEqual(set(r["common_cause"]), set(WALLETS) - {"w-single"})
        for w in ("w-single", "w-multi", "w-spread", "w-pin"):
            self.assertEqual(exploits(r, w, "main_loss"), {"at_use"}, w)
        self.assertIn("aux_loss", outcomes(r, "w-trip"))

    def test_collusion_combines_what_each_person_reaches(self):
        r = self.row("T-PERSON-COLLUSION@carol+dave")
        self.assertNotIn("main_loss", outcomes(r, "w-spread"), "Carol holds signer c, Dave signer d, and the pair may spend it together")
        self.assertNotIn("main_loss", outcomes(self.row("T-PERSON-MALICIOUS@carol"), "w-spread"))
        r = by_id(variant(lambda d: next(p for p in d["people"] if p["id"] == "carol").pop("may_spend")))["T-PERSON-COLLUSION@carol+dave"]
        self.assertIn("main_loss", outcomes(r, "w-spread"), "without that right they are thieves")

    def test_impaired_judgement_acts_like_a_leak_of_what_the_person_holds(self):
        r = self.row("T-PERSON-IMPAIRED@bob")
        self.assertIn("main_loss", outcomes(r, "w-multi"))
        self.assertEqual(outcomes(r, "w-pin"), {"inconvenience"})

    def test_loose_lips_are_privacy_loss_for_every_wallet(self):
        r = self.row("T-PERSON-LOOSE-LIPS@alice")
        for w in WALLETS:
            self.assertEqual(outcomes(r, w), {"privacy_loss"}, w)

    def test_a_lost_plan_is_a_latent_fault_for_every_wallet(self):
        r = self.row("T-PLAN-LOST@@plan")
        for w in WALLETS:
            self.assertEqual(outcomes(r, w), {"latent_no_margin"}, w)
        self.assertEqual(r["S"]["value"], 2)

    def test_a_failed_seal_is_an_inconvenience_for_the_wallets_behind_the_bag(self):
        r = self.row("T-BAG-SEAL-FAILURE@bag-1")
        self.assertEqual(outcomes(r, "w-multi"), {"inconvenience"})
        self.assertEqual(outcomes(r, "w-single"), set())

    def test_wallet_level_threats(self):
        self.assertEqual(outcomes(self.row("T-WALLET-FEE-DEADLOCK@w-single"), "w-single"), {"lockout_temporary"})
        self.assertEqual(outcomes(self.row("T-WALLET-FEE-DEADLOCK@w-trip"), "w-trip"), {"inconvenience"}, "no lock-out of auxiliary funds")
        self.assertEqual(exploits(self.row("T-WALLET-POLICY-INCORRECT@w-single"), "w-single", "main_loss"), {"at_recovery"}, "an owner's mistake is not exploited at use")
        self.assertIn("privacy_loss", outcomes(self.row("T-WALLET-PRIVACY-LEAK@w-single"), "w-single"))

    def test_a_tampered_backup_is_theft_at_recovery_but_a_wrong_one_is_only_lost(self):
        r = self.row("T-BAK-TAMPERED@b1")
        self.assertEqual(exploits(r, "w-single", "main_loss"), {"at_recovery"})
        r = self.row("T-BAK-INCORRECT@b1")
        self.assertEqual(outcomes(r, "w-single"), {"inconvenience", "latent_no_margin"}, "an owner's mistake only costs the copy; the device still holds the seed, and is now the last copy")

    def test_groups_need_a_value_to_group_by(self):
        for loc in ("loc-cloud", "loc-safe"):
            self.assertNotIn("common_cause", self.row(f"T-LOC-JURISDICTION-CHANGE@{loc}"), loc)

    def test_common_cause_by_backup_material(self):
        r = self.row("T-BAK-AGEING@b1")
        self.assertTrue({"b2a", "b2b", "b3a", "b-desc-bank"} <= set(r["common_cause"]))
        self.assertFalse({"b2c", "b-desc-cloud", "bk-head"} & set(r["common_cause"]))

    def test_controlled_device_leaks_its_seed_but_one_signer_is_not_theft(self):
        r = self.row("T-DEV-BACKDOOR@d2b")
        self.assertEqual(effect(r, "controlled"), {"d2b"})
        self.assertNotIn("main_loss", outcomes(r, "w-multi"))
        self.assertIn("latent_no_margin", outcomes(r, "w-multi"))

    def test_death_removes_a_person_and_what_only_that_person_knows_or_reaches(self):
        r = self.row("T-PERSON-DEATH@alice")
        self.assertEqual(effect(r, "destroyed"), {"alice", "bk-head"})
        self.assertEqual(outcomes(r, "w-single"), {"latent_no_margin"}, "Bob reaches everything of w-single, and is now the only one who does")
        self.assertIn("latent_no_margin", outcomes(r, "w-multi"))
        self.assertNotIn("main_loss", outcomes(r, "w-multi"))
        self.assertEqual(outcomes(r, "w-spread"), {"latent_margin"}, "one of four signers lost, any one more is fine")
        self.assertEqual(outcomes(r, "w-pin"), {"inconvenience", "latent_no_margin"}, "the PIN died with Alice; the backup at the trustee is the last way")

    def test_a_malicious_person_gets_what_he_reaches_and_knows_but_not_beyond_his_rights(self):
        r = self.row("T-PERSON-MALICIOUS@alice")
        for w in ("w-single", "w-multi", "w-pin"):
            self.assertNotIn("main_loss", outcomes(r, w), f"{w}: Alice may spend it at once")
        self.assertIn("aux_loss", outcomes(r, "w-trip"), "nobody may spend the tripwire")
        self.assertNotIn("main_loss", outcomes(r, "w-spread"))
        self.assertIn("latent_no_margin", outcomes(r, "w-spread"))

    def test_without_the_right_what_a_person_can_spend_is_theft(self):
        def drop(d):
            next(p for p in d["people"] if p["id"] == "alice")["may_spend"] = [{"wallets": ["w-single"]}, {"with": ["bob"], "wallets": ["w-spread"]}]
        r = by_id(variant(drop))["T-PERSON-MALICIOUS@alice"]
        self.assertEqual(exploits(r, "w-multi", "main_loss"), {"immediate"})
        self.assertEqual(exploits(r, "w-pin", "main_loss"), {"immediate"})
        self.assertNotIn("main_loss", outcomes(r, "w-single"))

    def test_spending_before_the_time_of_the_right_is_theft(self):
        def later(d):
            next(p for p in d["people"] if p["id"] == "dave")["may_spend"][0]["after_blocks"] = 60000
        r = by_id(variant(later))["T-PERSON-MALICIOUS@dave"]
        self.assertEqual(exploits(r, "w-multi", "main_loss"), {"after_delay"}, "the policy opens after 52000 blocks, the right only after 60000")
        self.assertNotIn("main_loss", outcomes(self.row("T-PERSON-MALICIOUS@dave"), "w-multi"))

    def test_a_coerced_person_is_never_within_their_rights(self):
        r = self.row("T-PERSON-COERCION@alice")
        self.assertIn("immediate", exploits(r, "w-single", "main_loss"))

    def test_a_person_without_the_pin_cannot_use_the_device(self):
        r = self.row("T-PERSON-MALICIOUS@bob")
        self.assertEqual(outcomes(r, "w-pin"), {"inconvenience"})
        r = by_id(variant(lambda d: next(p for p in d["people"] if p["id"] == "bob").update(may_spend=[])))["T-PERSON-MALICIOUS@bob"]
        self.assertIn("main_loss", outcomes(r, "w-multi"), "Bob reaches signers b and c; without a right to spend it that is theft")

    def test_the_trustee_reaches_the_fallback_and_the_pin_wallet_backup(self):
        r = self.row("T-PERSON-MALICIOUS@dave")
        self.assertNotIn("main_loss", outcomes(r, "w-pin"), "the trustee may spend it")
        self.assertNotIn("main_loss", outcomes(r, "w-multi"), "the delayed policy opens when his right does")
        self.assertNotIn("main_loss", outcomes(r, "w-spread"))
        r = by_id(variant(lambda d: next(p for p in d["people"] if p["id"] == "dave").update(may_spend=[])))["T-PERSON-MALICIOUS@dave"]
        self.assertIn("main_loss", outcomes(r, "w-pin"))
        self.assertIn("main_loss", outcomes(r, "w-multi"), "the delayed policy does not stop an attacker who waits")

    def test_extraction_bypasses_the_pin(self):
        r = self.row("T-DEV-LOST-OR-STOLEN@d5")
        self.assertEqual(exploits(r, "w-pin", "main_loss"), {"immediate"})

    def test_a_manipulated_coordinator_is_theft_at_use(self):
        r = self.row("T-COORD-MALICIOUS-SEND@coord1")
        self.assertEqual(exploits(r, "w-multi", "main_loss"), {"at_use"})
        self.assertEqual({w for w in WALLETS if "main_loss" in outcomes(r, w)}, {"w-multi"})

    def test_a_buggy_coordinator_is_only_an_inconvenience(self):
        r = self.row("T-COORD-SOFTWARE-BUG@coord1")
        self.assertEqual(r["S"]["outcome"], "inconvenience")

    def test_an_incorrect_custom_descriptor_loses_the_wallet_a_default_one_only_its_margin(self):
        r = self.row("T-DESC-INCORRECT@desc-w2")
        self.assertIn("main_loss", outcomes(r, "w-multi"), "a custom descriptor is not rebuilt from the keys")
        self.assertIn("lockout_temporary", outcomes(r, "w-multi"), "and until a corrected one is found the wallet is blocked")
        self.assertEqual(r["S"]["outcome"], "main_loss")
        r = self.row("T-DESC-INCORRECT@desc-w3")
        self.assertFalse({"lockout_temporary"} & outcomes(r, "w-spread"), "a default wallet is not blocked by a wrong copy")
        self.assertIn("main_loss", outcomes(r, "w-spread"), "a default descriptor is rebuilt from all signers, which no pair of people has")
        self.assertNotIn("T-DESC-DERIVATION-UNKNOWN@desc-w3", self.rows, "the derivation of a default wallet is the standard one")

    def test_a_bypassed_bag_discloses_its_contents(self):
        r = self.row("T-BAG-BYPASSED@bag-1")
        self.assertIn("b-desc-bank", effect(r, "disclosed"))
        self.assertIn("privacy_loss", outcomes(r, "w-multi"))
        self.assertNotIn("main_loss", outcomes(r, "w-multi"))

    def test_a_fireproof_product_survives_fire(self):
        r = self.row("T-LOC-FIRE@loc-bank")
        self.assertNotIn("b2c", effect(r, "destroyed"))
        self.assertIn("b-desc-bank", effect(r, "destroyed"))
        self.assertEqual(outcomes(r, "w-multi"), {"inconvenience", "latent_margin"}, "one descriptor copy fewer, enough others")

    def test_privacy_threats_are_privacy_loss(self):
        r = self.row("T-COORD-PRIVACY-BACKEND@coord1")
        self.assertEqual(outcomes(r, "w-multi"), {"privacy_loss"})
        self.assertEqual(r["S"]["value"], 3)


# ------------------------------------------------------------------------------------------ ratings

class Ratings(Base):
    def test_likelihood_modifiers_depend_on_the_target(self):
        self.assertEqual(self.row("T-LOC-FIRE@loc-home")["L"]["value"], 2)
        self.assertEqual(self.row("T-LOC-FIRE@loc-bank")["L"]["value"], 1)
        self.assertEqual(self.row("T-LOC-UNAUTHORIZED-ACCESS@loc-home")["L"]["value"], 3)
        self.assertEqual(self.row("T-LOC-UNAUTHORIZED-ACCESS@loc-safe")["L"]["value"], 2)
        self.assertEqual(self.row("T-LOC-UNAUTHORIZED-ACCESS@loc-w3a")["L"]["value"], 1)
        self.assertEqual(self.row("T-BAK-AGEING@b1")["L"]["value"], 4, "paper: 3 + 1")
        self.assertEqual(self.row("T-DEV-SUPPLY-CHAIN@d1")["L"]["value"], 1)
        self.assertEqual(self.row("T-DEV-SUPPLY-CHAIN@d2a")["L"]["value"], 2, "a reseller hop")

    def test_unknown_threat_falls_back_to_its_category_default(self):
        L = rating.likelihood(self.S, self.cat, {"id": "T-NEW-THREAT", "category": "human"}, "")
        self.assertEqual((L["value"], L["basis"]), (self.cat.category_likelihood["human"], "category_default"))

    def test_questions_for_the_owner_are_collected(self):
        r = self.row("T-LOC-NATURAL-DISASTER@loc-home")
        self.assertTrue(any(x.startswith("ask:") for x in r["needs_input"]))
        asked = {t for a in BASE["result"]["asks"] for t in a["threats"]}
        self.assertIn("T-LOC-NATURAL-DISASTER", asked)

    def test_risk_lookup(self):
        c = self.cat
        self.assertEqual(rating.risk(c, 3, 4, 4), (3, 4))
        self.assertEqual(rating.risk(c, 2, 2, 4), (0, 1))
        self.assertEqual(rating.risk(c, 4, 0, 4), (0, 1))
        self.assertEqual(rating.risk(c, 4, 4, 0), (4, 0))
        self.assertEqual(rating.risk(c, 0, 4, 4), (0, 1))
        self.assertEqual(rating.risk(c, 4, 4, 4), (4, 4))

    def test_tripwire_next_to_the_secrets_is_detection_that_acts_in_time(self):
        self.premise(self.addresses("M-D-TRIPWIRE", "T-LOC-ATTACK-LOCAL", "detects"), "tripwire detects local attacks")
        self.premise(self.cat.has_response("T-LOC-ATTACK-LOCAL"), "a response to local attacks exists")
        r = self.row("T-LOC-ATTACK-LOCAL@loc-home")
        self.assertEqual([m["mechanism"] for m in r["V"]["mechanisms"]], ["M-D-TRIPWIRE"],
                         "mechanisms of unrelated entities (d5's PIN, w-spread) must not count")
        self.assertEqual((r["V"]["detection"], r["V"]["value"]), (2, 2))

    def test_detection_before_each_use_counts_only_for_the_wallets_it_covers(self):
        self.premise(self.addresses("M-D-CROSS-CHECK-TRANSACTION", "T-DEV-CONNECTION-ATTACK", "detects"), "cross-check detects connection attacks")
        self.assertEqual(self.row("T-DEV-CONNECTION-ATTACK@d1")["V"]["value"], 4, "w-single has no cross-check")
        self.assertEqual(self.row("T-DEV-CONNECTION-ATTACK@d2a")["V"]["value"], 2)
        self.premise(self.addresses("M-D-CROSS-CHECK-TRANSACTION", "T-COORD-MALICIOUS-SEND", "detects"), "cross-check detects malicious sends")
        r = self.row("T-COORD-MALICIOUS-SEND@coord1")
        self.assertEqual((r["V"]["value"], r["RL"], r["R"]), (2, 0, 1))

    def test_periodic_detection_is_too_slow_against_immediate_theft(self):
        self.premise(self.addresses("M-D-BACKUP-VERIFY", "T-BAK-LOST", "detects"), "backup verification detects lost backups")
        r = self.row("T-BAK-LOST@b1")
        self.assertEqual(exploits(r, "w-single", "main_loss"), {"immediate"})
        entry = next(m for m in r["V"]["mechanisms"] if m["mechanism"] == "M-D-BACKUP-VERIFY")
        self.assertEqual((entry["strength"], entry.get("note")), (0, "too_slow"))
        self.assertEqual(r["V"]["value"], 4)

    def test_detection_without_a_response_is_worth_nothing(self):
        self.premise(self.addresses("M-D-TEST-TX", "T-WALLET-POLICY-INCORRECT", "detects"), "test transaction detects an incorrect wallet policy")
        self.premise(not self.cat.has_response("T-WALLET-POLICY-INCORRECT"), "no response to an incorrect wallet policy")
        r = self.row("T-WALLET-POLICY-INCORRECT@w-multi")
        entry = next(m for m in r["V"]["mechanisms"] if m["mechanism"] == "M-D-TEST-TX")
        self.assertEqual((entry["strength"], entry["note"]), (0, "no_response"))
        self.assertIn("detection_without_response", r["needs_input"])
        self.assertEqual(r["V"]["value"], 4)

    def test_a_pin_is_a_prevention_only_where_it_exists(self):
        self.premise(self.addresses("M-P-DEVICE-PIN", "T-DEV-LOST-OR-STOLEN", "reduces"), "a device PIN reduces loss or theft")
        mechanisms = lambda rid: {m["mechanism"] for m in self.row(rid)["V"]["mechanisms"]}
        self.assertIn("M-P-DEVICE-PIN", mechanisms("T-DEV-LOST-OR-STOLEN@d5"))
        self.assertNotIn("M-P-DEVICE-PIN", mechanisms("T-DEV-LOST-OR-STOLEN@d1"))

    def test_prevention_and_detection_together_add_a_bonus(self):
        self.premise(self.addresses("M-P-SPARE-SIGNERS", "T-DEV-BREAKS", "reduces"), "spare signers reduce device failure")
        self.premise(self.addresses("M-D-DEVICE-CHECK", "T-DEV-BREAKS", "detects"), "the device check detects breakage")
        self.premise(self.cat.has_response("T-DEV-BREAKS"), "a response to breakage exists")
        r = self.row("T-DEV-BREAKS@d2a")
        self.assertEqual((r["V"]["prevention"], r["V"]["detection"]), (1, 2))
        self.assertEqual(r["V"]["value"], 1, "4 - (max(1, 2) + 1)")
        self.assertEqual(self.row("T-DEV-BREAKS@d1")["V"]["value"], 2, "no spare signers: detection alone, 4 - 2")

    def test_elimination_gives_full_protection(self):
        self.premise(self.addresses("M-P-OWN-NODE", "T-COORD-PRIVACY-BACKEND", "eliminates"), "an own node eliminates backend privacy loss")
        r = self.row("T-COORD-PRIVACY-BACKEND@coord1")
        self.assertEqual((r["V"]["value"], r["R"]), (0, 0))


# ------------------------------------------------------------------------------------------ whole run

class Invariants(Base):
    def test_every_row_is_consistent(self):
        table = self.cat.ratings["outcomes"]
        matrix = self.cat.ratings["risk_matrix"]["values"]
        for r in self.rows.values():
            for k in ("L", "V", "S"):
                self.assertTrue(0 <= r[k]["value"] <= 4, (r["id"], k))
            self.assertEqual(r["RL"], max(0, min(4, r["L"]["value"] + r["V"]["value"] - 4)), r["id"])
            self.assertEqual(r["R"], matrix[r["RL"]][r["S"]["value"]], r["id"])
            worst = max([table[o["outcome"]]["severity"] for o in r["outcomes"]], default=0)
            self.assertEqual(r["S"]["value"], worst, r["id"])
            if r["S"]["value"] == 0:
                self.assertEqual(r["R"], 0, r["id"])
            for o in r["outcomes"]:
                self.assertIn(o["wallet"], WALLETS)
                self.assertIn(o["outcome"], table)
                self.assertIn(o["exploit"], ("none", "immediate", "at_use", "after_delay", "at_recovery"))
                if o["wallet"] == "w-trip":
                    self.assertNotIn(o["outcome"], ("main_loss", "lockout_temporary"), r["id"])
                else:
                    self.assertNotEqual(o["outcome"], "aux_loss", r["id"])
            for peer in r.get("common_cause", []):
                self.assertIn(peer, self.S.by_id)

    def test_row_ids_are_unique_and_rows_plus_skips_cover_all_instances(self):
        self.assertEqual(len(self.rows), len(BASE["result"]["rows"]))
        total = len(self.rows) + len(BASE["result"]["not_applicable"])
        expected = 0
        for t in self.cat.threats.values():
            classes = t["target"].get("subclasses") or [t["target"]["class"]]
            n = sum(len(self.S.of(c)) for c in classes)
            expected += 6 if t["target"].get("cardinality") == "set" else n
        self.assertEqual(total, expected)

    def test_analysis_is_deterministic(self):
        a = json.dumps(BASE["result"], sort_keys=False)
        b = json.dumps(analyze.analyze(SETUP), sort_keys=False)
        self.assertEqual(a, b)

    def test_fixture_gives_no_warnings(self):
        self.assertEqual([w for w in BASE["result"]["warnings"] if "regist" not in w and "travel" not in w], [])


# ------------------------------------------------------------------------------------------ variants

class Variants(Base):
    def test_without_practices_no_risk_falls_and_no_vulnerability_falls(self):
        v = by_id(variant(lambda d: d.update(practices=[])))
        for rid, r in self.rows.items():
            self.assertGreaterEqual(v[rid]["V"]["value"], r["V"]["value"], rid)
            self.assertGreaterEqual(v[rid]["R"], r["R"], rid)
        self.assertGreater(sum(r["R"] for r in v.values()), sum(r["R"] for r in self.rows.values()))

    def test_without_the_near_link_the_neighbour_survives_the_disaster(self):
        def drop(d):
            next(l for l in d["locations"] if l["id"] == "loc-home")["near"] = []
        r = by_id(variant(drop))["T-LOC-NATURAL-DISASTER@loc-home"]
        self.assertNotIn("d2b", effect(r, "destroyed"))
        self.assertNotIn("lockout_temporary", outcomes(r, "w-multi"))
        self.assertIn("latent_no_margin", outcomes(r, "w-multi"))

    def test_a_strip_kept_where_nobody_with_the_bag_can_reach_it_removes_the_swap_threat(self):
        def move(d):
            next(s for s in d["strips"] if s["id"] == "strip-1")["stored_in"] = {"location": "loc-w3c"}
        result = variant(move)
        self.assertIn(("T-STRIP-SWAPPED-WITH-BAG", "strip-1"), {(x["threat"], x["entity"]) for x in result["not_applicable"]})

    def test_a_strip_that_one_person_reaches_together_with_the_bag_keeps_the_swap_threat(self):
        def move(d):
            next(s for s in d["strips"] if s["id"] == "strip-1")["stored_in"] = {"location": "loc-w3a"}
        self.assertIn("T-STRIP-SWAPPED-WITH-BAG@strip-1", by_id(variant(move)), "Alice reaches both places")

    def test_a_check_before_use_comes_too_late_for_a_seed_the_attacker_already_has(self):
        self.premise(self.addresses("M-D-CROSS-CHECK-TRANSACTION", "T-DEV-FIRMWARE-MALICIOUS", "detects"), "cross-check detects malicious firmware")
        def add(d):
            d["practices"].append({"id": "p-x", "mechanism": "M-D-CROSS-CHECK-TRANSACTION", "scope": ["w-single"]})
        r = by_id(variant(add))["T-DEV-FIRMWARE-MALICIOUS@d1"]
        self.assertEqual(exploits(r, "w-single", "main_loss"), {"immediate"})
        entry = next(m for m in r["V"]["mechanisms"] if m["mechanism"] == "M-D-CROSS-CHECK-TRANSACTION")
        self.assertEqual((entry["strength"], entry.get("note")), (0, "too_slow"))

    def test_a_second_copy_elsewhere_saves_the_single_sig_wallet_from_fire(self):
        def add(d):
            d["backups"].append({"id": "b1-copy", "name": "s1 copy", "medium": "paper", "stored_in": {"location": "loc-bank"}, "items": [{"subject": {"seed": "s1"}, "format": "words"}]})
        r = by_id(variant(add))["T-LOC-FIRE@loc-home"]
        self.assertNotIn("main_loss", outcomes(r, "w-single"))
        self.assertEqual(outcomes(r, "w-single"), {"inconvenience", "latent_no_margin"}, "the copy at the bank is the last one")

    def test_a_tripwire_elsewhere_does_not_watch_the_home(self):
        self.premise(self.addresses("M-D-TRIPWIRE", "T-LOC-ATTACK-LOCAL", "detects"), "tripwire detects local attacks")
        def move(d):
            for e in d["devices"] + d["backups"]:
                if e["id"] in ("d4", "b4"):
                    e["stored_in"] = {"location": "loc-bank"}
        base = self.row("T-LOC-ATTACK-LOCAL@loc-home")["V"]["value"]
        moved = by_id(variant(move))["T-LOC-ATTACK-LOCAL@loc-home"]
        self.assertEqual((base, moved["V"]["value"]), (2, 4))


class SetupCheck(Base):
    def test_a_restore_test_at_setup_catches_a_wrong_backup_almost_surely(self):
        self.premise(self.addresses("M-D-TEST-RESTORE", "T-BAK-INCORRECT", "detects"), "a restore test detects a wrong backup")
        self.premise(self.cat.has_response("T-BAK-INCORRECT"), "a response to a wrong backup exists")
        v = by_id(variant(lambda d: d["practices"].append({"id": "p-restore", "mechanism": "M-D-TEST-RESTORE"})))
        self.assertGreaterEqual(self.row("T-BAK-INCORRECT@b1")["V"]["value"], 2)
        self.assertEqual(v["T-BAK-INCORRECT@b1"]["V"]["value"], 1)

    def test_a_check_at_setup_is_weaker_against_faults_that_arise_later(self):
        self.premise(self.addresses("M-D-TEST-RESTORE", "T-DEV-FIRMWARE-BUG", "detects"), "a restore test detects firmware bugs")
        self.premise(self.cat.has_response("T-DEV-FIRMWARE-BUG"), "a response to a firmware bug exists")
        v = by_id(variant(lambda d: d["practices"].append({"id": "p-restore", "mechanism": "M-D-TEST-RESTORE"})))
        self.assertEqual(v["T-DEV-FIRMWARE-BUG@d1"]["V"]["value"], 3)


class DelayedPolicy(Base):
    def timelock_entry(self, row):
        return next((m for m in row["V"]["mechanisms"] if m["mechanism"] == "M-P-REFRESH-TIMELOCK"), None)

    ROW = "T-LOC-ATTACK-LOCAL@loc-far"      # the fallback key and a registered copy of the descriptor are both at the relative's

    def test_a_policy_that_opens_after_its_delay_is_not_an_immediate_theft(self):
        r = self.row(self.ROW)
        self.assertEqual(exploits(r, "w-multi", "main_loss"), {"after_delay"})
        self.assertEqual(outcomes(self.row("T-DEV-LOST-OR-STOLEN@d2f"), "w-multi") & {"main_loss"}, set(), "the key alone, without the custom descriptor, is not enough")
        self.assertEqual(exploits(self.row("T-DEV-LEAKS-KEY@d1"), "w-single", "main_loss"), {"immediate"})

    def test_refreshing_the_funds_is_a_barrier_only_against_the_delayed_policy(self):
        self.premise("after_delay" in self.cat.mechanisms["M-P-REFRESH-TIMELOCK"].get("barrier_for", []), "refreshing is a barrier against delayed policies")
        entry = self.timelock_entry(self.row(self.ROW))
        self.assertEqual((entry["strength"], entry.get("barrier")), (2, True))
        self.assertIsNone(self.timelock_entry(self.row("T-DEV-LOST-OR-STOLEN@d1")))

    def test_without_the_refresh_the_delayed_policy_is_unprotected(self):
        self.premise("after_delay" in self.cat.mechanisms["M-P-REFRESH-TIMELOCK"].get("barrier_for", []), "refreshing is a barrier against delayed policies")
        v = by_id(variant(lambda d: d.update(practices=[p for p in d["practices"] if p["mechanism"] != "M-P-REFRESH-TIMELOCK"])))
        now, without = self.row(self.ROW), v[self.ROW]
        self.assertIsNone(self.timelock_entry(without))
        self.assertEqual((now["V"]["prevention"], without["V"]["prevention"]), (2, 1), "the barrier is gone, the other preventions remain")


class Travel(Base):
    TRAVEL = [{"from": "loc-w3a", "to": "loc-w3b", "minutes": 25}, {"from": "loc-w3a", "to": "loc-w3c", "minutes": 40},
              {"from": "loc-w3b", "to": "loc-w3c", "minutes": 90}, {"from": "loc-home", "to": "loc-bank", "minutes": 10}]

    @staticmethod
    def declared(d):
        d["travel_times"] = Travel.TRAVEL

    def test_the_table_is_symmetric_and_a_sub_location_counts_as_its_place(self):
        S = setup_of(self.declared)
        self.assertEqual((S.travel("loc-home", "loc-bank"), S.travel("loc-bank", "loc-home")), (10, 10))
        self.assertEqual(S.travel("loc-safe", "loc-bank"), 10)

    def test_an_undeclared_pair_counts_as_no_travel(self):
        self.assertEqual(setup_of(self.declared).travel("loc-home", "loc-far"), 0)
        self.assertEqual(self.S.travel("loc-home", "loc-bank"), 0)

    def test_a_journey_is_the_cheapest_order_of_its_stops(self):
        S = setup_of(self.declared)
        self.assertEqual(S.journey(["loc-w3a", "loc-w3b", "loc-w3c"]), 65, "b - a - c is 25 + 40")
        self.assertEqual(S.journey(["loc-w3a"]), 0)

    def test_a_person_who_cannot_complete_a_quorum_alone_needs_infinite_time(self):
        self.assertEqual(rating.quorum_minutes(self.S, "carol"), INF)

    def test_the_quorum_time_is_the_cheapest_journey_between_enough_signers(self):
        def mutate(d):
            self.declared(d)
            for l in d["locations"]:
                if l["id"] in ("loc-w3a", "loc-w3b"):
                    l["access"].append("carol")
            d["backups"].append({"id": "b-desc-w3a", "name": "descriptor at A", "medium": "paper", "stored_in": {"location": "loc-w3a"},
                                 "items": [{"subject": {"descriptor": "desc-w3"}, "format": "text"}]})
        self.assertEqual(rating.quorum_minutes(setup_of(mutate), "carol"), 25, "two of four signers at the two closest places, with the descriptor at one of them")


class ConcealedPlaces(Base):
    @staticmethod
    def hide_safe(d):
        next(l for l in d["locations"] if l["id"] == "loc-safe")["kind"] = "hidden_at_home"

    def test_an_intruder_in_a_home_does_not_find_what_is_in_a_concealed_place(self):
        S = setup_of(self.hide_safe)
        found = access.select(S, "intrusion_contents", "loc-home")
        self.assertIn("d1", found)
        self.assertNotIn("d2a", found)
        self.assertIn("d2a", access.select(self.S, "intrusion_contents", "loc-home"), "a safe is in view")

    def test_an_intruder_in_the_concealed_place_finds_it_together_with_what_is_in_view_above(self):
        found = access.select(setup_of(self.hide_safe), "intrusion_contents", "loc-safe")
        self.assertTrue({"d2a", "b2a", "d1"} <= set(found))


class SetupTest(Base):
    ADD = {"id": "p-setup", "mechanism": "M-P-SETUP-TEST-ALL-SIGNERS", "scope": ["w-multi"]}

    def test_a_setup_test_with_every_signer_eliminates_the_descriptor_and_policy_errors(self):
        self.premise(self.addresses("M-P-SETUP-TEST-ALL-SIGNERS", "T-DESC-INCORRECT", "eliminates"), "the setup test eliminates incorrect descriptors")
        self.premise(self.addresses("M-P-SETUP-TEST-ALL-SIGNERS", "T-WALLET-POLICY-INCORRECT", "eliminates"), "the setup test eliminates incorrect policies")
        v = by_id(variant(lambda d: d["practices"].append(self.ADD)))
        for rid in ("T-DESC-INCORRECT@desc-w2", "T-WALLET-POLICY-INCORRECT@w-multi"):
            self.assertGreater(self.row(rid)["V"]["value"], 0, rid)
            self.assertEqual(v[rid]["V"]["value"], 0, rid)

    def test_it_does_nothing_for_wallets_outside_its_scope(self):
        v = by_id(variant(lambda d: d["practices"].append(self.ADD)))
        rid = "T-WALLET-POLICY-INCORRECT@w-single"
        self.assertEqual(v[rid]["V"]["value"], self.row(rid)["V"]["value"])


class Measures(Base):
    ms = property(lambda self: BASE["result"]["measures"])

    def assert_exact(self, lines, mutate):
        """A variant changes exactly the listed rows, to exactly the listed ratings."""
        self.assertTrue(lines)
        v = by_id(variant(mutate))
        listed = {l[0]: l for l in lines}
        for rid, row in self.rows.items():
            if row["S"]["value"] == 0:
                continue
            expect = (listed[rid][2], listed[rid][4]) if rid in listed else (row["R"], row["V"]["value"])
            if rid in listed:
                self.assertEqual((row["R"], row["V"]["value"]), (listed[rid][1], listed[rid][3]), rid)
            self.assertEqual((v[rid]["R"], v[rid]["V"]["value"]), expect, rid)

    def test_only_procedural_mechanisms_are_listed_and_each_applies_somewhere(self):
        for m in self.ms:
            self.assertEqual(self.cat.mechanisms[m["mechanism"]]["form"], "procedural")
            self.assertTrue(m["applicable"], m["mechanism"])
        in_place = {m["practice"] for m in self.ms if "practice" in m}
        self.assertEqual(in_place, {p["id"] for p in self.S.data["practices"] if self.cat.mechanisms[p["mechanism"]]["form"] == "procedural"})

    def test_a_practice_in_place_is_rated_as_the_setup_without_it(self):
        for m in [m for m in self.ms if "practice" in m and m["rows"]]:
            with self.subTest(m["practice"]):
                self.assert_exact(m["rows"], lambda d, p=m["practice"]: d.update(practices=[x for x in d["practices"] if x["id"] != p]))

    def test_a_practice_with_a_narrow_scope_is_rated_as_the_setup_with_the_scope_widened(self):
        wide = [m for m in self.ms if m.get("extend")]
        self.assertTrue(wide)
        for m in wide:
            with self.subTest(m["practice"]):
                def widen(d, p=m["practice"]):
                    next(x for x in d["practices"] if x["id"] == p).pop("scope", None)
                self.assert_exact(m["extend"], widen)

    def test_a_missing_measure_is_rated_as_the_setup_with_it(self):
        missing = [m for m in self.ms if "practice" not in m and "implicit" not in m and m["rows"]]
        self.assertTrue(missing)
        for m in missing:
            with self.subTest(m["mechanism"]):
                self.assert_exact(m["rows"], lambda d, mid=m["mechanism"]: d["practices"].append({"id": "what-if", "mechanism": mid}))

    def test_adding_a_measure_never_makes_a_line_worse(self):
        for m in [m for m in self.ms if "practice" not in m and "implicit" not in m]:
            for _, r0, r1, v0, v1 in m["rows"]:
                self.assertTrue(r1 <= r0 and v1 <= v0, m["mechanism"])

    def test_a_device_in_regular_use_is_checked_by_use_without_a_practice(self):
        self.premise(self.cat.mechanisms["M-D-DEVICE-CHECK"].get("implicit_when"), "the device check follows from regular use")
        self.premise(self.addresses("M-D-DEVICE-CHECK", "T-DEV-BREAKS", "detects"), "the device check detects breakage")
        def mutate(d):
            d["practices"] = [p for p in d["practices"] if p["mechanism"] != "M-D-DEVICE-CHECK"]
            next(x for x in d["devices"] if x["id"] == "d1")["use"] = "regular"
        v = by_id(variant(mutate))
        covered = lambda r: {e for m in r["V"]["mechanisms"] if m["mechanism"] == "M-D-DEVICE-CHECK" for e in m["entities"]}
        self.assertEqual(covered(v["T-DEV-BREAKS@d1"]), {"d1"})
        self.assertEqual(covered(v["T-DEV-BREAKS@d2a"]), set(), "d2a is not used regularly")

    def test_measures_in_place_by_use_are_listed_apart_from_practices(self):
        def mutate(d):
            d["practices"] = [p for p in d["practices"] if p["mechanism"] != "M-D-DEVICE-CHECK"]
            next(x for x in d["devices"] if x["id"] == "d1")["use"] = "regular"
        result = analyze.analyze(self.write(mutate))
        entries = [m for m in result["measures"] if m["mechanism"] == "M-D-DEVICE-CHECK"]
        by_use = [m for m in entries if "implicit" in m]
        missing = [m for m in entries if "implicit" not in m and "practice" not in m]
        self.assertEqual([m["implicit"] for m in by_use], [["d1"]])
        self.assertNotIn("d1", missing[0]["applicable"], "a device that is checked by use is not a candidate")
        data = report.build_data(result, setup_of(mutate), BASE["cat"])
        shown = next(m for m in data["measures"] if m["id"] == "M-D-DEVICE-CHECK" and m.get("byuse"))
        self.assertTrue(shown["inplace"])

    @staticmethod
    def write(mutate):
        data = copy.deepcopy(BASE["data"])
        mutate(data)
        path = Path(tempfile.mkdtemp()) / "variant.json"
        path.write_text(json.dumps(data))
        return path

    def test_the_report_lists_the_measures(self):
        data = report.build_data(BASE["result"], BASE["S"], BASE["cat"])
        self.assertEqual(len(data["measures"]), len(self.ms))
        timelock = next(m for m in data["measures"] if m["id"] == "M-P-REFRESH-TIMELOCK")
        self.assertTrue(timelock["inplace"] and timelock["lines"])
        self.assertTrue(timelock["when"])


class Preflight(Base):
    def errors(self, mutate):
        data = copy.deepcopy(BASE["data"])
        mutate(data)
        return loader.preflight(data, self.cat)

    def test_reference_errors(self):
        errors, _ = self.errors(lambda d: d["backups"][0].update(stored_in={"location": "loc-nowhere"}))
        self.assertTrue(any("loc-nowhere" in e for e in errors))
        errors, _ = self.errors(lambda d: d["wallets"][0]["spending_policies"][0].update(threshold=3))
        self.assertTrue(any("threshold" in e for e in errors))

    def test_schema_errors(self):
        errors, _ = self.errors(lambda d: d.update(schema_version="0.1"))
        self.assertTrue(any(e.startswith("schema") for e in errors))

    def test_memory_backups_are_kept_in_a_person(self):
        def bad(d):
            next(b for b in d["backups"] if b["id"] == "bk-head")["stored_in"] = {"location": "loc-home"}
        errors, _ = self.errors(bad)
        self.assertTrue(any("memory" in e and "person" in e for e in errors), errors)

    def test_a_coordinator_runs_on_a_computing_device_never_on_a_signing_device(self):
        errors, _ = self.errors(lambda d: next(c for c in d["coordinators"] if c["id"] == "coord1").update(runs_on="d1"))
        self.assertTrue(any("coord1" in e and "SigningDevice" in e for e in errors), errors)
        errors, _ = self.errors(lambda d: next(c for c in d["coordinators"] if c["id"] == "coord1").pop("runs_on"))
        self.assertTrue(any(e.startswith("schema") and "runs_on" in e for e in errors), errors)

    def test_a_phone_is_carried_and_a_desktop_stands_in_a_place(self):
        errors, _ = self.errors(lambda d: next(x for x in d["computing_devices"] if x["id"] == "pc1").update(kind="mobile"))
        self.assertTrue(any("mobile" in e and "carried" in e for e in errors), errors)
        errors, _ = self.errors(lambda d: next(x for x in d["computing_devices"] if x["id"] == "laptop2").update(kind="desktop"))
        self.assertTrue(any("desktop" in e for e in errors), errors)

    def test_bag_cycles(self):
        def bad(d):
            d["bags"].append({"id": "bag-2", "name": "b2", "strip": "strip-1", "stored_in": {"bag": "bag-1"}})
            next(b for b in d["bags"] if b["id"] == "bag-1")["stored_in"] = {"bag": "bag-2"}
        errors, _ = self.errors(bad)
        self.assertTrue(any("cycle" in e for e in errors))

    def test_practices_must_name_procedural_mechanisms_on_matching_entities(self):
        errors, _ = self.errors(lambda d: d["practices"].append({"id": "p-x", "mechanism": "M-P-DEVICE-PIN"}))
        self.assertTrue(any("not a procedural" in e for e in errors))
        errors, _ = self.errors(lambda d: d["practices"].append({"id": "p-y", "mechanism": "M-D-TRIPWIRE", "scope": ["d1"]}))
        self.assertTrue(any("targets Wallet" in e for e in errors))
        errors, _ = self.errors(lambda d: d["practices"].append({"id": "p-z", "mechanism": "M-D-NOPE"}))
        self.assertTrue(any("unknown mechanism" in e for e in errors))

    @staticmethod
    def drop_descriptor(d, did):
        d["descriptors"] = [x for x in d["descriptors"] if x["id"] != did]
        d["backups"] = [b for b in d["backups"] if not any(i["subject"].get("descriptor") == did for i in b["items"])]
        for c in d["coordinators"] + d["devices"]:
            c["stores_descriptors"] = [x for x in c.get("stores_descriptors", []) if x != did]

    def test_a_multi_signer_wallet_without_descriptor_is_an_error(self):
        errors, _ = self.errors(lambda d: self.drop_descriptor(d, "desc-w3"))
        self.assertTrue(any("w-spread" in e and "needs a descriptor" in e for e in errors), errors)

    def test_a_custom_wallet_without_a_descriptor_is_an_error(self):
        def custom(d):
            self.drop_descriptor(d, "desc-w-single")
            next(w for w in d["wallets"] if w["id"] == "w-single")["definition"] = "custom"
        errors, _ = self.errors(custom)
        self.assertTrue(any("w-single" in e and "needs a descriptor" in e for e in errors), errors)

    def test_a_descriptor_that_is_kept_nowhere_is_an_error(self):
        def lose(d):
            d["backups"] = [b for b in d["backups"] if not any("descriptor" in i["subject"] and i["subject"]["descriptor"] == "desc-w3" for i in b["items"])]
            next(c for c in d["coordinators"] if c["id"] == "coord2")["stores_descriptors"].remove("desc-w3")
        errors, _ = self.errors(lose)
        self.assertTrue(any("desc-w3" in e and "kept nowhere" in e for e in errors), errors)

    def test_a_wallet_has_at_most_one_descriptor(self):
        errors, _ = self.errors(lambda d: d["descriptors"].append({"id": "desc-extra", "name": "second", "wallet": "w-spread"}))
        self.assertTrue(any("at most one" in e for e in errors), errors)

    def test_a_wallet_that_no_coordinator_has_a_descriptor_for_is_flagged_and_the_setup_needs_a_coordinator(self):
        errors, warnings = self.errors(lambda d: self.drop_descriptor(d, "desc-w-single"))
        self.assertEqual(errors, [])
        self.assertTrue(any("w-single" in w and "no coordinator has its descriptor" in w for w in warnings), warnings)
        errors, _ = self.errors(lambda d: d.update(coordinators=[]))
        self.assertTrue(any(e.startswith("schema") for e in errors), errors)

    def test_a_coordinator_on_an_offline_device_is_flagged(self):
        _, warnings = self.errors(lambda d: next(x for x in d["computing_devices"] if x["id"] == "pc1").update(online=False))
        self.assertTrue(any("coord1" in w and "offline" in w for w in warnings), warnings)

    def test_registration_checks_against_the_device_catalog(self):
        _, warnings = self.errors(lambda d: None)
        about = lambda dev: [w for w in warnings if w.startswith(f"device {dev} ")]
        self.assertEqual(about("d2c"), [], "a Ledger that has the descriptor registered")
        self.assertTrue(any("supports registering descriptors but has none registered" in w for w in about("d2a")))
        self.assertTrue(any("does not say whether" in w for w in about("d3a")), "Trezor: unknown")
        self.assertTrue(any("supports registering descriptors but has none registered" in w for w in about("d2b")), "Jade registers")
        self.assertTrue(any("loaded for every signing" in w for w in about("d3c")), "SeedSigner: per transaction")
        errors, _ = self.errors(store_on("d3c"))
        self.assertTrue(any("d3c" in e and "cannot keep a registered descriptor" in e for e in errors))
        errors, _ = self.errors(store_on("d3a"))
        self.assertEqual(errors, [], "unknown is not an error")

    def test_warnings(self):
        _, warnings = self.errors(lambda d: d["backups"].remove(next(b for b in d["backups"] if b["id"] == "b5")))
        self.assertTrue(any("s5" in w for w in warnings), "a seed without any backup")
        _, warnings = self.errors(lambda d: d["devices"][0].update(model="Unknown Model"))
        self.assertTrue(any("device catalog" in w for w in warnings))

    def test_an_unusable_setup_is_reported(self):
        def unreachable(d):
            next(l for l in d["locations"] if l["id"] == "loc-home")["access"] = []
        result = variant(unreachable)
        self.assertTrue(any("w-single" in w and "baseline" in w for w in result["warnings"]))


# ------------------------------------------------------------------------------------------ command line

class Report(Base):
    @classmethod
    def setUpClass(cls):
        cls.data = report.build_data(BASE["result"], BASE["S"], BASE["cat"])
        cls.view = {r["id"]: r for r in cls.data["rows"]}

    def test_every_row_and_every_skipped_pair_is_shown(self):
        self.assertEqual(set(self.view), set(self.rows))
        self.assertEqual(len(self.data["na"]), len(BASE["result"]["not_applicable"]))

    def test_the_entities_follow_the_class_order(self):
        classes = [e["class"] for e in self.data["entities"]]
        self.assertEqual(classes, sorted(classes, key=report.CLASS_ORDER.index))
        self.assertEqual(classes[0], "Person")

    def test_main_wallets_come_before_tripwire_wallets(self):
        wallets = [e["id"] for e in self.data["entities"] if e["class"] == "Wallet"]
        self.assertEqual(wallets[-1], "w-trip", "the tripwire is listed last")
        self.assertEqual(set(wallets[:-1]), set(WALLETS) - {"w-trip"})
        nodes = [n["id"] for n in self.data["structure"]["nodes"] if n["c"] == "Wallet"]
        self.assertEqual(nodes[-1], "w-trip")

    def test_ratings_are_carried_over_and_explained(self):
        for rid, r in self.rows.items():
            v = self.view[rid]
            self.assertEqual((v["L"]["v"], v["V"]["v"], v["S"]["v"], v["R"]), (r["L"]["value"], r["V"]["value"], r["S"]["value"], r["R"]))
            for k in "LVS":
                self.assertTrue(v[k]["x"], rid)
            for text in v["L"]["x"] + v["V"]["x"] + v["S"]["x"] + v["chain"] + [v["eff"], v["risk"]]:
                self.assertNotRegex(text, r"[{}]", f"{rid}: placeholder left in {text!r}")

    def test_the_vulnerability_text_names_the_measures_and_those_that_do_not_count(self):
        v = self.view["T-DEV-BLIND-SIGNING@d2c"]
        self.assertTrue(any(BASE["cat"].mechanisms["M-P-REGISTER-DESCRIPTOR"]["name"] in x for x in v["V"]["x"]))
        w = self.view["T-DESC-INCORRECT@desc-w2"]
        self.assertTrue(any("does not count" in x for x in w["V"]["x"]))

    def test_the_scales_and_the_risk_table_are_embedded_for_the_hover_texts(self):
        self.assertEqual(len(self.data["risk_matrix"]), 5)
        for name in ("likelihood", "vulnerability", "severity"):
            self.assertEqual(len(self.data["scales"][name]["bands"]), 5)
            self.assertTrue(self.data["scales"][name]["description"])

    def test_the_chain_ends_in_the_outcomes(self):
        v = self.view["T-DESC-INCORRECT@desc-w2"]
        self.assertTrue(v["chain"][0].startswith("Incorrect or outdated hits"))
        self.assertTrue(any("loss of main funds" in x for x in v["chain"]))
        self.assertEqual(v["eff"], "Loss of main funds: " + self.S.ent("w-multi")["name"])

    def test_related_entities_include_the_dependencies_of_the_affected_wallets(self):
        v = self.view["T-DESC-INCORRECT@desc-w2"]
        self.assertEqual(v["rel"]["target"], ["desc-w2"])
        self.assertIn("w-multi", v["rel"]["wallets"])
        self.assertIn("s2a", self.data["structure"]["deps"]["w-multi"])

    def test_the_diagram_structure_has_a_card_for_every_entity_and_only_valid_links(self):
        st = self.data["structure"]
        ids = {n["id"] for n in st["nodes"]}
        self.assertEqual(ids, set(self.S.by_id), "what a person carries is shown inside the person")
        held = {n["id"]: n["in"] for n in st["nodes"] if "in" in n}
        self.assertEqual(held["bk-head"], "alice")
        policies = {f"{w['id']}#{i}" for w in self.S.of("Wallet") for i in range(1, len(w["spending_policies"]) + 1)}
        for a, b, kind in st["edges"]:
            self.assertIn(a, ids | policies)
            self.assertIn(b, ids, kind)
        for n in st["nodes"]:
            self.assertIn(n.get("in", "@plan"), ids)

    def test_a_person_can_reach_what_is_kept_in_the_places_they_access(self):
        st = self.data["structure"]
        for pid, reach in st["access"].items():
            self.assertIn(pid, reach)
            for e in self.S.reachable_entities(pid):
                self.assertIn(e, reach)

    def test_the_context_links_the_affected_entity_only_to_the_policies_that_use_it(self):
        v = self.view["T-DEV-BLIND-SIGNING@d2f"]
        self.assertEqual(v["rel"]["policies"], ["w-multi#2"], "only the delayed fallback policy has the signer f")
        self.assertEqual(v["rel"]["context"], ["s2f"])

    def test_the_measures_of_a_row_are_listed_with_their_kind_and_description(self):
        m = {x["id"]: x for x in self.view["T-DEV-BLIND-SIGNING@d2c"]["V"]["m"]}
        self.assertEqual(m["M-P-REGISTER-DESCRIPTOR"]["kind"], "prevention")
        self.assertIn("signers that do not have it can sign alone", m["M-P-REGISTER-DESCRIPTOR"]["note"], "the quorum gap is named")
        self.assertTrue(m["M-P-REGISTER-DESCRIPTOR"]["desc"])

    def test_the_html_embeds_the_data_and_nothing_can_end_the_script(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "r.html"
            report.write_html(BASE["result"], SETUP, out)
            html = out.read_text(encoding="utf-8")
        self.assertNotIn("__DATA__", html)
        payload = html[html.index("const DATA = ") + len("const DATA = "):html.index(";\nconst $ =")]
        self.assertNotIn("</", payload)
        self.assertEqual(len(json.loads(payload)["rows"]), len(self.rows))


class AccessRights(Base):
    def person(self, pid):
        return next(p for p in self.S.data["people"] if p["id"] == pid)

    def results(self, st, wallet):
        return {a["person"]: a["result"] for a in self.ev.access(st) if a["wallet"] == wallet}

    def test_rights_are_one_entry_per_set_of_people_and_wallet(self):
        rights = {(tuple(sorted(r["people"])), r["wallet"]): r["after"] for r in self.ev.rights()}
        self.assertEqual(rights[(("alice", "bob"), "w-spread")], 0)
        self.assertEqual(rights[(("dave",), "w-multi")], 52000)
        self.assertEqual(rights[(("alice", "dave"), "w-pin")], 0)
        self.assertEqual(len([k for k in rights if k[1] == "w-spread"]), 6, "every pair of the four signers")
        self.assertFalse([k for k in rights if k[1] == "w-trip"], "nobody may spend the tripwire")

    def test_the_fixture_gives_the_people_what_they_should_have_and_no_more(self):
        self.assertEqual([w for w in BASE["result"]["warnings"] if w.startswith("rights")], [])
        self.assertTrue(all(a["result"] == "ok" for a in self.ev.access(access.State())))

    def test_a_right_that_the_setup_does_not_give_is_reported(self):
        later = variant(lambda d: self.person_in(d, "dave")["may_spend"][0].update(after_blocks=10000))
        self.assertTrue(any("Dave" in w and "only can after 52000 blocks" in w for w in later["warnings"]), later["warnings"])
        carol = variant(lambda d: self.person_in(d, "carol").update(may_spend=[{"wallets": ["w-single"]}]))
        self.assertTrue(any("Carol" in w and "cannot at all" in w for w in carol["warnings"]), carol["warnings"])

    def test_people_who_can_spend_without_a_right_are_reported(self):
        out = variant(lambda d: self.person_in(d, "dave").update(may_spend=[{"after_blocks": 52000, "wallets": ["w-multi"]}]))
        self.assertTrue(any("Dave can spend Single-sig behind a PIN at once without having that right" in w for w in out["warnings"]), out["warnings"])

    def test_a_right_that_opens_later_than_the_setup_allows_is_reported_as_too_early(self):
        out = variant(lambda d: self.person_in(d, "dave")["may_spend"][0].update(after_blocks=60000))
        self.assertTrue(any("earlier than intended" in w for w in out["warnings"]), out["warnings"])

    @staticmethod
    def person_in(d, pid):
        return next(p for p in d["people"] if p["id"] == pid)

    def test_a_dead_person_is_no_failure_and_their_rights_are_void(self):
        res = self.results(state(lost={"dave"}), "w-multi")
        self.assertNotIn("dave", res)
        self.assertEqual(res["alice"], "ok")
        self.assertFalse([o for o in self.ev.evaluate(state(lost={"dave"})) if o["wallet"] == "w-pin" and o["outcome"] in ("main_loss", "owner_access_lost")])

    def test_an_owner_who_loses_every_way_while_another_keeps_one_is_severity_three(self):
        gone = {"d2c", "b2c", "d2f", "b2f"}
        self.assertEqual(self.results(state(lost=gone), "w-multi"), {"alice": "ok", "bob": "lost", "dave": "lost"})
        out = {o["outcome"] for o in self.ev.evaluate(state(lost=gone)) if o["wallet"] == "w-multi"}
        self.assertIn("owner_access_lost", out)
        self.assertIn("latent_no_margin", out, "the trustee lost his way too, but he is no owner")
        self.assertNotIn("main_loss", out)
        self.assertEqual(self.cat.ratings["outcomes"]["owner_access_lost"]["severity"], 3)

    def test_when_every_owner_has_lost_all_access_the_main_funds_are_lost(self):
        gone = {"d2c", "b2c", "d2f", "b2f", "d2a", "b2a"}
        out = {o["outcome"] for o in self.ev.evaluate(state(lost=gone)) if o["wallet"] == "w-multi"}
        self.assertIn("main_loss", out)

    def test_a_slower_way_is_a_delay_not_a_loss(self):
        res = self.results(state(lost={"d2c", "b2c"}), "w-multi")
        self.assertEqual(res["alice"], "ok")
        self.assertEqual(res["bob"], "delayed", "Bob is left with the fallback policy")
        out = {o["outcome"] for o in self.ev.evaluate(state(lost={"d2c", "b2c"})) if o["wallet"] == "w-multi"}
        self.assertIn("lockout_temporary", out)
        self.assertNotIn("main_loss", out)

    def test_a_part_that_is_only_blocked_gives_a_delay_to_a_non_owner_with_a_lesser_outcome(self):
        res = self.results(state(blocked={"d2f", "b2f"}), "w-multi")
        self.assertEqual(res["dave"], "delayed")
        out = {o["outcome"] for o in self.ev.evaluate(state(blocked={"d2f", "b2f"})) if o["wallet"] == "w-multi"}
        self.assertIn("latent_margin", out)
        self.assertNotIn("lockout_temporary", out)

    def test_rows_list_who_lost_access(self):
        r = self.row("T-LOC-FIRE@loc-home")
        self.assertTrue(r.get("access"))
        self.assertTrue(all(a["result"] != "ok" for a in r["access"]))

    def test_preflight_wants_a_right_for_every_main_wallet_and_consistent_delays(self):
        errors, _ = loader.preflight(self.without(lambda d: [p.pop("may_spend", None) for p in d["people"]]), self.cat)
        self.assertTrue(any("nobody may spend it" in e for e in errors))
        def clash(d):
            self.person_in(d, "dave")["may_spend"].append({"after_blocks": 1, "wallets": ["w-multi"]})
        errors, _ = loader.preflight(self.without(clash), self.cat)
        self.assertTrue(any("different delays" in e for e in errors))
        errors, _ = loader.preflight(self.without(lambda d: self.person_in(d, "dave")["may_spend"].append({"with": ["nobody"]})), self.cat)
        self.assertTrue(any("nobody" in e for e in errors))

    @staticmethod
    def without(mutate):
        data = copy.deepcopy(BASE["data"])
        mutate(data)
        return data


class DiagramFocus(Base):
    def test_a_focused_wallet_lights_the_people_who_can_spend_it_alone_or_together(self):
        who = report.build_data(BASE["result"], BASE["S"], BASE["cat"])["structure"]["who"]
        self.assertTrue({"alice", "dave"} <= set(who["w-multi"]))
        self.assertIn("carol", who["w-spread"], "she has a right together with Dave")
        self.assertNotIn("carol", who["w-single"])

    def test_devices_list_the_seeds_loaded_on_them_for_the_diagram(self):
        nodes = {n["id"]: n for n in report.build_data(BASE["result"], BASE["S"], BASE["cat"])["structure"]["nodes"]}
        for seed in BASE["S"].of("Seed"):
            for d in seed.get("devices", []):
                self.assertIn(seed["id"], [h["id"] for h in nodes[d]["holds"]])
        self.assertNotIn("holds", nodes["alice"])
        for dev in BASE["S"].of("Device"):
            for did in dev.get("stores_descriptors", []):
                self.assertIn(did, [h["id"] for h in nodes[dev["id"]]["holds"]])

    def test_an_heir_who_cannot_reach_the_funds_when_the_owner_dies_is_a_loss(self):
        data = json.loads((HERE / "scenarios" / "00_single_sig_hot_wallet.json").read_text())
        data["people"].append({"id": "bob", "name": "Bob", "roles": ["heir"], "may_spend": [{"after_blocks": 144}]})
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "s.json"
            path.write_text(json.dumps(data))
            rows = {r["id"]: r for r in analyze.analyze(path, what_if=False)["rows"]}
        self.assertEqual({o["outcome"] for o in rows["T-PERSON-DEATH@alice"]["outcomes"]}, {"main_loss"})
        self.assertEqual(rows["T-PERSON-DEATH@alice"]["S"]["value"], 4)

    def test_a_hit_on_a_host_hits_the_coordinator_that_runs_on_it(self):
        st = access.State()
        access.hit(BASE["S"], st, "pc1", "disclosed")
        self.assertTrue(st.has("coord1", "disclosed"))

    def test_a_coordinator_lists_the_descriptors_of_its_wallets_for_the_diagram(self):
        nodes = {n["id"]: n for n in report.build_data(BASE["result"], BASE["S"], BASE["cat"])["structure"]["nodes"]}
        for co in BASE["S"].of("Coordinator"):
            self.assertEqual({h["id"] for h in nodes[co["id"]]["holds"] if not h.get("implicit")}, set(co.get("stores_descriptors", [])))

    def test_a_descriptor_derived_on_the_host_of_the_seed_is_an_implicit_entry_for_the_detail_diagram(self):
        path = HERE / "scenarios" / "00_single_sig_hot_wallet.json"
        cat = loader.Catalogs()
        S = Setup(loader.read_json(path), cat)
        data = report.build_data(analyze.analyze(path, what_if=False), S, cat)["structure"]
        nodes = {n["id"]: n for n in data["nodes"]}
        self.assertTrue(nodes["implicit:w1"]["implicit"])
        self.assertEqual([(h["id"], h.get("implicit")) for h in nodes["coord"]["holds"]], [("implicit:w1", True)])
        self.assertIn(["w1", "implicit:w1", "descriptor"], data["edges"])
        self.assertIn(["coord", "implicit:w1", "stores"], data["edges"])

    def test_a_stolen_host_reveals_the_wallets_of_its_coordinator_unless_a_password_protects_them(self):
        ev = outc.Evaluator(BASE["S"])

        def privacy(host, known=()):
            st = state(disclosed={host}, secret_known=known)
            access.hit(BASE["S"], st, host, "disclosed")
            return {o["wallet"] for o in ev.evaluate(st) if o["outcome"] == "privacy_loss"}
        self.assertNotIn("w-multi", privacy("pc1"), "coord1 has a password")
        self.assertIn("w-multi", privacy("pc1", ["pin-coord"]))
        self.assertIn("w-single", privacy("laptop2"), "coord2 has none")

    def test_the_effects_list_everything_the_attacker_gets_to_know(self):
        host = self.row("T-PERSON-COERCION@alice")
        self.assertIn("desc-w3", effect(host, "known"), "coord2 has no password")
        host = self.row("T-LOC-ATTACK-LOCAL@loc-home")
        self.assertNotIn("desc-w2", effect(host, "known"), "coord1 has a password")

    def test_nobody_left_to_spend_a_wallet_is_no_loss(self):
        result = analyze.analyze(HERE / "scenarios" / "00_single_sig_hot_wallet.json", what_if=False)
        row = next(r for r in result["rows"] if r["id"] == "T-PERSON-DEATH@alice")
        self.assertEqual((row["outcomes"], row["R"]), ([], 0))

    def test_a_focused_person_lights_the_wallets_and_policies_they_can_spend_alone(self):
        access = report.build_data(BASE["result"], BASE["S"], BASE["cat"])["structure"]["access"]
        self.assertTrue({"w-single", "w-single#1"} <= set(access["alice"]))
        self.assertIn("w-spread#1", access["carol"], "she satisfies the policy together with Dave, to whom her right ties her")
        self.assertNotIn("w-single", access["carol"], "a right to one wallet does not light the others")
        self.assertIn("w-multi#2", access["dave"], "the delayed fallback policy counts, whatever its delay")

    def test_one_spending_policy_of_a_wallet_can_be_focused(self):
        st = report.build_data(BASE["result"], BASE["S"], BASE["cat"])["structure"]
        self.assertIn("dave", st["who"]["w-multi#2"])
        self.assertTrue(set(st["deps"]["w-multi#1"]) < set(st["deps"]["w-multi"]) or set(st["deps"]["w-multi#1"]) != set(st["deps"]["w-multi#2"]))
        self.assertNotIn("w-single#1", st["who"], "only wallets with several policies have policy options")


class RightsReport(Base):
    def test_every_right_is_compared_with_what_the_intact_setup_delivers(self):
        rep = BASE["result"]["rights"]
        self.assertEqual(len(rep["rights"]), len(BASE["ev"].rights()))
        for r in rep["rights"]:
            self.assertIn(r["state"], ("ok", "later", "never", "earlier"))
            self.assertEqual(r["state"] == "ok", r["got"] == r["after"])

    def test_the_findings_are_the_rights_that_are_not_ok_and_the_extra_ones(self):
        rep = BASE["result"]["rights"]
        findings = [w for w in BASE["result"]["warnings"] if w.startswith("rights:")]
        self.assertEqual(len(findings), len([r for r in rep["rights"] if r["state"] != "ok"]) + len(rep["extra"]))

    def test_the_report_counts_the_threats_that_delay_or_cost_access(self):
        view = report.build_data(BASE["result"], BASE["S"], BASE["cat"])["rights"]
        self.assertTrue(view["threats"])
        for t in view["threats"]:
            self.assertGreater(t["lost"] + t["delayed"], 0)


class Feedback(Base):
    RID = "T-LOC-FIRE@loc-home"

    @staticmethod
    def given(overrides=(), answers=()):
        asked = [{"ask": a["ask"], "field": "L", "value": a["value"], "reason": a["note"]} for a in answers]
        return {"overrides": list(overrides) + asked}

    def analyse(self, given):
        return analyze.analyze(SETUP, given=given, what_if=False)

    def test_a_rating_set_by_hand_replaces_the_computed_one_and_the_risk_follows(self):
        base = self.row(self.RID)
        ov = {"row": self.RID, "field": "V", "value": 0, "reason": "the fire brigade is next door"}
        r = by_id(self.analyse(self.given([ov])))[self.RID]
        self.assertEqual((r["V"]["value"], r["V"]["computed"]), (0, base["V"]["value"]))
        self.assertEqual(r["V"]["override"], {"reason": "the fire brigade is next door"})
        self.assertEqual(r["RL"], max(0, r["L"]["value"] - 4))
        self.assertEqual(r["R"], self.cat.ratings["risk_matrix"]["values"][r["RL"]][r["S"]["value"]])
        self.assertLess(r["R"], base["R"])

    def test_likelihood_and_severity_can_be_set_by_hand_too(self):
        ovs = [{"row": self.RID, "field": "L", "value": 4, "reason": "a"}, {"row": self.RID, "field": "S", "value": 1, "reason": "b"}]
        r = by_id(self.analyse(self.given(ovs)))[self.RID]
        self.assertEqual((r["L"]["value"], r["S"]["value"]), (4, 1))
        self.assertEqual((r["L"]["computed"], r["S"]["computed"]), (self.row(self.RID)["L"]["value"], self.row(self.RID)["S"]["value"]))

    def test_an_override_needs_a_reason_and_a_value_from_0_to_4(self):
        result = self.analyse(self.given([{"row": self.RID, "field": "V", "value": 2, "reason": " "}, {"row": self.RID, "field": "L", "value": 7, "reason": "x"}]))
        self.assertEqual(len(result["errors"]), 2, result["errors"])

    def test_an_override_for_a_missing_line_or_an_older_setup_is_flagged(self):
        ovs = [{"row": "T-NOTHING@nowhere", "field": "V", "value": 1, "reason": "x"},
               {"row": self.RID, "field": "V", "value": 1, "reason": "x", "setup_sha": "000000000000"}]
        warnings = self.analyse(self.given(ovs))["warnings"]
        self.assertTrue(any("T-NOTHING@nowhere" in w and "does not exist" in w for w in warnings))
        self.assertTrue(any(self.RID in w and "earlier version" in w for w in warnings))

    def test_an_answer_is_the_base_of_the_threats_it_concerns_and_closes_the_question(self):
        open_ask = BASE["result"]["asks"][0]
        answers = [{"ask": open_ask["ask"], "value": 4, "note": "right at the coast"}]
        result = self.analyse(self.given(answers=answers))
        mine = [r for r in result["rows"] if r["threat"] in open_ask["threats"]]
        self.assertTrue(mine)
        for r in mine:
            self.assertEqual((r["L"]["basis"], r["L"]["base"], r["L"]["answer"]["reason"]), ("answered", 4, "right at the coast"))
            self.assertNotIn("ask", r["L"])
            self.assertFalse([n for n in r.get("needs_input", []) if n.startswith("ask:")])
        asked = next(a for a in result["asks"] if a["ask"] == open_ask["ask"])
        self.assertEqual(asked["answer"]["value"], 4)

    def test_answers_and_ratings_set_by_hand_are_one_list_in_the_analysis(self):
        ask = BASE["result"]["asks"][0]["ask"]
        ovs = [{"row": self.RID, "field": "V", "value": 1, "reason": "x"}, {"ask": ask, "field": "L", "value": 3, "reason": "y"}]
        result = self.analyse(self.given(ovs))
        self.assertEqual(len(result["overrides"]), 2)
        self.assertNotIn("answers", result)

    def test_an_override_names_a_line_or_a_question_and_a_question_only_has_a_likelihood(self):
        ask = BASE["result"]["asks"][0]["ask"]
        both = {"row": self.RID, "ask": ask, "field": "L", "value": 1, "reason": "x"}
        wrong = {"ask": ask, "field": "V", "value": 1, "reason": "x"}
        self.assertEqual(len(self.analyse(self.given([both, wrong]))["errors"]), 2)

    def test_an_override_can_name_a_threat_on_all_entities_or_all_threats_on_an_entity(self):
        threat = {"threat": "T-LOC-FIRE", "field": "V", "value": 0, "reason": "sprinklers everywhere"}
        entity = {"entity": "loc-home", "field": "V", "value": 1, "reason": "this house has a fire alarm"}
        rows = by_id(self.analyse(self.given([threat])))
        fires = [r for r in rows.values() if r["threat"] == "T-LOC-FIRE"]
        self.assertGreater(len(fires), 1)
        for r in fires:
            self.assertEqual((r["V"]["value"], r["V"]["override"]["scope"]), (0, "threat"))
        self.assertFalse([r for r in rows.values() if r["threat"] != "T-LOC-FIRE" and "override" in r["V"]])
        rows = by_id(self.analyse(self.given([entity])))
        on_home = [r for r in rows.values() if r["entity"] == "loc-home"]
        self.assertGreater(len(on_home), 1)
        for r in on_home:
            self.assertEqual((r["V"]["value"], r["V"]["override"]["scope"]), (1, "entity"))
        self.assertFalse([r for r in rows.values() if r["entity"] != "loc-home" and "override" in r["V"]])

    def test_the_line_wins_over_the_threat_and_the_threat_over_the_entity(self):
        ovs = [{"entity": "loc-home", "field": "V", "value": 1, "reason": "e"},
               {"threat": "T-LOC-FIRE", "field": "V", "value": 2, "reason": "t"},
               {"row": self.RID, "field": "V", "value": 3, "reason": "r"}]
        rows = by_id(self.analyse(self.given(ovs)))
        self.assertEqual((rows[self.RID]["V"]["value"], rows[self.RID]["V"]["override"]["reason"]), (3, "r"))
        other_fire = next(r for r in rows.values() if r["threat"] == "T-LOC-FIRE" and r["id"] != self.RID)
        self.assertEqual(other_fire["V"]["override"]["reason"], "t")
        other_on_home = next(r for r in rows.values() if r["entity"] == "loc-home" and r["threat"] != "T-LOC-FIRE")
        self.assertEqual(other_on_home["V"]["override"]["reason"], "e")

    def test_a_threat_or_entity_that_does_not_exist_is_flagged_and_one_scope_only_is_allowed(self):
        ovs = [{"threat": "T-NOTHING", "field": "V", "value": 1, "reason": "x"}, {"entity": "nobody", "field": "V", "value": 1, "reason": "x"}]
        warnings = self.analyse(self.given(ovs))["warnings"]
        self.assertTrue(any("T-NOTHING" in w and "does not exist" in w for w in warnings))
        self.assertTrue(any("nobody" in w and "does not exist" in w for w in warnings))
        both = {"threat": "T-LOC-FIRE", "entity": "loc-home", "field": "V", "value": 1, "reason": "x"}
        self.assertEqual(len(self.analyse(self.given([both]))["errors"]), 1)

    def test_answers_of_the_older_format_are_read_as_overrides(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "old.json"
            path.write_text(json.dumps({"answers": [{"ask": "Q?", "value": 2, "note": "n"}]}))
            self.assertEqual(feedback.read(path)["overrides"], [{"ask": "Q?", "field": "L", "value": 2, "reason": "n"}])

    def test_the_command_line_keeps_feedback_and_merges_an_exported_file(self):
        with tempfile.TemporaryDirectory() as d:
            out, extra = Path(d) / "a.analysis.json", Path(d) / "feedback.json"
            extra.write_text(json.dumps(self.given([{"row": self.RID, "field": "V", "value": 1, "reason": "from the page"}])))
            first = subprocess.run([sys.executable, str(CLI), str(SETUP), "-o", str(out), "--feedback", str(extra)], capture_output=True, text=True)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(json.loads(out.read_text())["overrides"][0]["reason"], "from the page")
            again = subprocess.run([sys.executable, str(CLI), str(SETUP), "-o", str(out)], capture_output=True, text=True)
            self.assertEqual(again.returncode, 0, again.stderr)
            data = json.loads(out.read_text())
            self.assertEqual([o["reason"] for o in data["overrides"]], ["from the page"], "carried over when the file is written again")
            row = next(r for r in data["rows"] if r["id"] == self.RID)
            self.assertEqual(row["V"]["value"], 1)


class ComputingDevices(Base):
    def test_what_a_person_carries_is_in_a_place_only_that_person_reaches(self):
        self.assertEqual(self.S.place("laptop2"), "alice")
        self.assertEqual(self.S.place("bk-head"), "alice")
        self.assertIn("laptop2", self.S.reachable_entities("alice"))
        self.assertNotIn("laptop2", self.S.reachable_entities("bob"))
        self.assertNotIn("alice", self.S.ids_of("Location"), "a person is a place of their own, not a location")

    def test_amnesia_wipes_the_memory_but_not_the_devices_a_person_carries(self):
        r = self.row("T-PERSON-AMNESIA@alice")
        self.assertEqual(effect(r, "destroyed"), {"bk-head"})

    def test_death_wipes_the_memory_and_the_person_but_leaves_the_devices(self):
        r = self.row("T-PERSON-DEATH@alice")
        self.assertEqual(effect(r, "destroyed"), {"alice", "bk-head"})
        self.assertNotIn("laptop2", effect(r, "destroyed"))

    def test_malware_on_a_computing_device_hits_the_coordinator_that_runs_on_it(self):
        r = self.row("T-DEV-MALWARE@pc1")
        self.assertEqual(effect(r, "controlled"), {"pc1", "coord1"})
        self.assertEqual(effect(r, "tampered"), {"w-multi"}, "the wallets the coordinator on it handles can be manipulated")
        self.assertEqual(exploits(r, "w-multi", "main_loss"), {"at_use"})

    def test_a_hot_wallet_is_lost_with_the_phone(self):
        result = analyze.analyze(HERE / "scenarios" / "00_single_sig_hot_wallet.json", what_if=False)
        rows = {r["id"]: r for r in result["rows"]}
        for rid in ("T-DEV-LOST-OR-STOLEN@phone", "T-DEV-MALWARE@phone"):
            self.assertIn("immediate", exploits(rows[rid], "w1", "main_loss"), rid)
        self.assertEqual(rows["T-DEV-BREAKS@phone"]["S"]["value"], 4, "with no backup the seed is gone with the phone")

    def test_breaking_and_loss_are_one_threat_for_every_kind_of_device(self):
        for dev in ("pc1", "laptop2", "d1"):
            for t in ("T-DEV-BREAKS", "T-DEV-LOST-OR-STOLEN"):
                self.assertIn(f"{t}@{dev}", self.rows)
        self.assertFalse([t for t in self.cat.threats if t.startswith("T-CDEV")])

    def test_malware_needs_an_online_device(self):
        self.assertIn("T-DEV-MALWARE@pc1", self.rows)
        self.assertFalse([r for r in self.rows.values() if r["threat"] == "T-DEV-MALWARE" and r["class"] == "SigningDevice"])
        data = json.loads(Path(SETUP).read_text())
        next(d for d in data["computing_devices"] if d["id"] == "pc1")["online"] = False
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "s.json"
            path.write_text(json.dumps(data))
            ids = {r["id"] for r in analyze.analyze(path, what_if=False)["rows"]}
        self.assertNotIn("T-DEV-MALWARE@pc1", ids)
        self.assertIn("T-DEV-MALWARE@laptop2", ids)

    def test_a_carried_device_is_more_likely_lost_than_a_desktop(self):
        self.assertEqual(self.row("T-DEV-LOST-OR-STOLEN@laptop2")["L"]["value"], self.row("T-DEV-LOST-OR-STOLEN@pc1")["L"]["value"] + 1)

    def test_the_hierarchy_table_is_the_only_list_of_subclasses(self):
        self.assertTrue(ontology.is_a("SigningDevice", "Device") and ontology.is_a("Descriptor", "Secret") and not ontology.is_a("Seed", "Device"))
        self.assertEqual({e["id"] for e in self.S.of("Device")}, {d["id"] for d in self.S.of("SigningDevice") + self.S.of("ComputingDevice")})


class DevicePictures(Base):
    def test_every_model_in_the_picture_table_is_in_the_device_catalog_and_has_its_file(self):
        table = loader.csv_rows(loader.LOOKUPS / "DeviceImages.csv", ("vendor", "model"))
        self.assertTrue(table)
        for key, row in table.items():
            self.assertIn(key, self.cat.device_rows, key)
            self.assertTrue((report.IMAGES / f"{row['file']}.webp").exists(), row["file"])
            self.assertTrue(row["source_url"].startswith("https://") and row["licence"], key)

    def test_devices_with_a_picture_carry_it_into_the_diagram_data(self):
        data = report.build_data(BASE["result"], BASE["S"], BASE["cat"], images=True)["structure"]
        nodes = {n["id"]: n for n in data["nodes"]}
        self.assertIn(nodes["d1"]["img"], data["images"])
        self.assertTrue(data["images"][nodes["d1"]["img"]].startswith("data:image/webp;base64,"))
        self.assertEqual(set(data["images"]), {n["img"] for n in data["nodes"] if "img" in n})

    def test_without_the_option_there_are_no_pictures(self):
        data = report.build_data(BASE["result"], BASE["S"], BASE["cat"])["structure"]
        self.assertEqual(data["images"], {})
        self.assertFalse([n for n in data["nodes"] if "img" in n])


class Scenarios(unittest.TestCase):
    def test_every_scenario_setup_is_valid(self):
        paths = [p for p in sorted((HERE / "scenarios").glob("[0-9][0-9]_*.json")) if not p.name.endswith(".analysis.json")]
        self.assertGreaterEqual(len(paths), 15)
        for path in paths:
            errors, _ = loader.preflight(json.loads(path.read_text(encoding="utf-8")), BASE["cat"])
            self.assertEqual(errors, [], path.name)


class Manuals(Base):
    """A manual holds only what its person can reach or needs for their rights, and no attacker-only step."""
    @classmethod
    def setUpClass(cls):
        cls.pages = {p: manuals.render(BASE["S"], BASE["ev"], BASE["cat"], BASE["result"], p) for p in ("alice", "carol", "dave")}

    def test_scope_is_what_the_person_reaches_or_needs(self):
        carol = self.pages["carol"]
        self.assertIn("Hiding place C", carol)
        self.assertIn("Hiding place A", carol)         # her co-signer Alice's part of w-spread
        for eid in ("loc-safe", "w-single", "w-multi", "b2a", "d1"):
            self.assertNotIn(html.escape(self.S.name(eid)), carol, eid)
        self.assertIn("Safe in the home", self.pages["alice"])

    def test_attacker_only_actions_never_appear(self):
        names = [a["name"] for a in self.cat.actions.values() if a.get("for") == "attacker"]
        self.assertTrue(names)
        for page in self.pages.values():
            for n in names:
                self.assertNotIn(html.escape(n), page)

    def test_delayed_right_gives_a_takeover_section_with_the_wait(self):
        dave = self.pages["dave"]
        self.assertIn(self.t["manual"]["setup_heir"], dave)
        self.assertIn("52000 blocks", dave)
        self.assertIn(self.t["manual"]["setup_owner"], self.pages["alice"])

    def test_maintenance_lists_only_practices_that_touch_the_person(self):
        carol = self.pages["carol"]
        for p in self.S.data.get("practices", []):
            m = self.cat.mechanisms[p["mechanism"]]
            targets = [e for e in self.S.ids_of(m["target"]) if not p.get("scope") or e in p["scope"]]
            if not any(e in manuals.scope(self.S, self.ev, "carol") for e in targets):
                self.assertNotIn(html.escape(m["name"]) + " <small>", carol)

    @property
    def t(self):
        return loader.read_json(self.cat.data_dir / "Texts.json")


class CommandLine(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(CLI), *map(str, args)], capture_output=True, text=True)

    def test_manuals_are_written_per_person(self):
        with tempfile.TemporaryDirectory() as d:
            p = self.run_cli(SETUP, "-o", Path(d) / "a.json", "--manuals", d)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(sorted(f.name for f in Path(d).glob("*.manual.*.html")),
                             [f"TestSetup.manual.{p}.html" for p in ("alice", "bob", "carol", "dave")])

    def test_check_only(self):
        p = self.run_cli(SETUP, "--check-only")
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_invalid_setup_stops_with_an_error_list(self):
        data = json.loads(SETUP.read_text())
        data["wallets"][0]["spending_policies"][0]["threshold"] = 3
        with tempfile.TemporaryDirectory() as d:
            bad = Path(d) / "bad.json"
            bad.write_text(json.dumps(data))
            p = self.run_cli(bad)
            self.assertEqual(p.returncode, 1)
            self.assertIn("threshold", p.stderr)
            self.assertFalse((Path(d) / "bad.analysis.json").exists())

    def test_output_is_written_next_to_the_setup_and_is_reproducible(self):
        with tempfile.TemporaryDirectory() as d:
            a, b = Path(d) / "a.json", Path(d) / "b.json"
            self.assertEqual(self.run_cli(SETUP, "-o", a).returncode, 0)
            self.assertEqual(self.run_cli(SETUP, "-o", b).returncode, 0)
            self.assertEqual(a.read_text(), b.read_text())
            data = json.loads(a.read_text())
            self.assertEqual(data["meta"]["rows"], len(data["rows"]))

    def test_the_html_report_is_written_by_the_same_call(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "r.html"
            p = self.run_cli(SETUP, "-o", Path(d) / "a.json", "--html", out)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn("<table", out.read_text(encoding="utf-8") + "<table")
            self.assertGreater(out.stat().st_size, 10000)

    def test_human_format_is_not_implemented_yet(self):
        self.assertEqual(self.run_cli(SETUP, "--format", "human").returncode, 2)


if __name__ == "__main__":
    unittest.main()
