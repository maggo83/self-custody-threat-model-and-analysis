# Notes for working on this repository

Read `README.md` first for what the tool does and how to run it, and `ARCHITECTURE.md` for where each kind of knowledge lives.
This file holds what is not obvious from the code.

## Commands

```sh
# tests (about 4 min; the fixture is analysed once, the scenarios and the extensibility test run the CLI); run from GenericThreatModelling
cd GenericThreatModelling && python3 -m unittest discover -s tests

# regenerate the dummy analysis, report and manuals (run from the repository root)
python3 GenericThreatModelling/engine/threat_analysis.py SpecificThreatAnalysis/DummySetup.json \
  -o SpecificThreatAnalysis/DummySetup.analysis.json --html --images --manuals

# regenerate the 15 scenario reports
cd GenericThreatModelling/tests/scenarios && python3 generate.py
```

Analysis files, reports and manuals (`*.analysis.json`, `*.report.html`, `*.manual.*.html`, `tests/scenarios/index.html`) are generated and ignored by git. Regenerate them to look at a change in `engine/report.template.html`, the catalogs or the engine; run the tests first.
Python 3.12, standard library plus `jsonschema` (Draft 2020-12), tests with `unittest` only.
`CUSTODY_DATA_ROOT` points the engine at another copy of the knowledge files (schema, catalogs, lookups); the extensibility test uses it.

## Principle: one source per fact

Duplicated knowledge drifts, so each fact has one home and the rest is derived or checked by a test (`SingleSource` in `tests/test_engine.py`).

| Fact | Home |
|---|---|
| Classes, parents, flags (`abstract`, `nested`, `singleton`, `place`, `placed_by`, `credential`, `information`, `active`, `inherits_status`, `privacy`, `catalog`), collection names, defaults, per-class `if`/`then` rules | `SetupOntology.schema.json`, read by `engine/ontology.py` and `graph.py` |
| Which class a reference must point to | `x-ref` marks in `SetupOntology.schema.json`, checked by `loader.references()` |
| Derived attributes, impact selectors, what an asset/actor is, goals, margin probes, setup checks | `GenericThreatModelling/AccessModel.json` |
| What spending, obtaining a secret or unlocking a device needs | `RecoveryActions.json`, executed by `engine/access.py` |
| Threat categories, sources (and which are malicious), phases, status kinds (and which leak) | `$defs` of `GenericThreatModelling/ThreatModelCommon.schema.json`, read by `engine/vocab.py` |
| Base likelihood and its modifiers | inside each threat in `Threats.json`, defaults per category in `category_likelihood` |
| Location kinds, which are remote | `Lookups/LocationKinds.csv` |
| Outcomes, their severity and the rules that produce them | `Ratings.json`; `Texts.json` must have the same keys |
| Lanes, colours, icons, every user-visible text | `Texts.json` (`display`, `classes`, `manual`, ...); the report template has no class literals |

When adding a class, enum value, selector, outcome or category: change the home, then let the tests tell what else must follow
(diagram in `SetupOntology.md`, `display` table, texts). `tests/test_extensibility.py` is the worked example of a new class.
Prefer attributes, conditions and actions in the catalogs over new special cases in the engine; if the engine would need an `if` on a class
or entity name, the knowledge belongs in data. Merge threats only if they are addressed
by the same mechanisms; identical effects alone are not a reason (send, receive and change address threats stay separate).

## Engine

Pipeline: `loader` (catalogs, schema validation, preflight incl. the declared checks) -> `graph.Setup` (entities, containers, places, reach,
derived attributes, expression language) -> `access` (access trees from the action catalog, agents: people and attacker, `State` of status
flags) -> `outcomes.Evaluator` (facts per wallet and state -> outcome rules) -> `rating` (likelihood, vulnerability from mechanisms, severity,
risk) -> `analyze` (all threats on all entities, overrides, what-if, deductive section) -> `report` plus `report.template.html` (one offline
page, data inserted at `__DATA__`) and `manuals` (one HTML per person).
Others: `deductive` (cut and path sets), `measures` (what-if for mechanisms), `feedback` (overrides), `ontology`, `vocab`,
`threat_analysis` (CLI, `--serve` local save server).

Modelling decisions that are easy to get wrong:

- **Theft needs the whole tree.** The attacker spends only when he can complete the spend action: enough signers *and* the descriptor
  (an explicit copy, or the public keys of all signers of a default wallet). Two of four leaked keys of a default multisig without a
  descriptor copy are `latent`, not theft. The goal action is `AccessModel.goals.spend`.
- **Statuses.** `destroyed`, `unavailable`, `disclosed`, `controlled`, `tampered`, `faulty`. People see `destroyed/tampered/faulty` as broken
  (strict mode adds `unavailable`); the attacker reaches what is `disclosed` or what he commands (`controlled`, or `tampered` and `active`),
  and commanding an entity bypasses the steps it `guards` (PIN of a stolen device). Mistakes (`T-BAK-INCORRECT`, `T-DESC-INCORRECT`, ...)
  are `faulty`. A leak on a host propagates to `inherits_status` classes placed in it (coordinator on a device).
- **Margin** is relative to the intact setup: `latent_margin` says a probe would now cause what it would not before.
- **Devices:** `Device` is abstract with `SigningDevice` (seeds and descriptors, never hosts a coordinator) and `ComputingDevice`
  (mobile, laptop, desktop; hosts coordinators, can hold seeds as a hot wallet; attribute `online`, default true).
  A coordinator must `runs_on` a computing device. A controlled computing device also controls the coordinator on it.
- **People as carriers:** `stored_in {person}` puts an item in the person's memory or on them (internally a virtual place `person:<id>`).
  Death, incapacity and amnesia wipe memory contents, never devices carried. Memory backups must be stored in a person;
  a mobile is always carried, a desktop never.
- **Access rights:** `may_spend` on a person says who may spend which wallet and after how long, alone or with others.
  Outcomes compare this with what the setup delivers. If everybody who may spend a main wallet is gone, there is no loss outcome;
  if one is alive and cannot reach it, there is.
- **Descriptors and coordinators:** a coordinator builds transactions and queries the network and needs the descriptor of each wallet it
  coordinates; a wallet has any number of coordinators (no wallet-to-coordinator link). `Coordinator.stores_descriptors` lists explicit copies.
  Only copies kept where the seed is not also available are written in the setup; the default descriptor of a wallet is implicit where its
  seeds are. An attacker knows a wallet's descriptor from an explicit copy, or, for a default wallet, from the public
  keys of all its signers (a known seed, or a known descriptor that contains the signer): action `R-ACCESS-DESCRIPTOR`. Privacy is lost
  when the descriptor is known or a coordinator is controlled. A disclosed host leaks the descriptors of its coordinators unless the coordinator has a password the attacker
  does not know; a disclosed signing device leaks only without PIN or with the PIN known. `wallet.descriptor` is derived from `descriptor.wallet`.
  Diagram: explicit descriptors are entities; implicit ones (`implicit:<wallet>`) appear only in the detail diagram of a row.
- **Overrides:** an override sets a rating for a line, for a threat on all entities, or for all threats on one entity (line wins over
  threat over entity), or answers a question for the owners. A reason is required. Overrides live in the analysis file.
- **Implicit measures:** a procedural mechanism can count as present because of how an entity is used (`implicit_when`), without a practice.

## Report page

Tabs: table, diagram, measures, access, fault trees (deductive cut and path sets). Diagram: people, locations, secrets, wallets and plan in lanes. Devices and people are boxes that hold what is in them
(software, seeds, descriptors, backups) in sub-lanes; lanes nobody uses are not drawn. Focus mode starts only from the focus list;
inside it a click on a person, wallet or one of several policies moves the focus, a click on anything outside the focus ends it.
"Color by risk" can be switched to a color per type, where backups are a darker shade of what they hold.
Lane, colour and icon per class come from `Texts.json` -> `display`; a test fails if a class is missing or the template names a class.

## Manuals

`--manuals [DIR]` writes one standalone HTML per person: rights, what they reach, getting started (owners: the setup actions; others:
the takeover after the delay without the owners), spending as checklists from the access tree pruned to what their group can do
(attacker-only actions never appear), maintenance from the practices that touch what they reach, incidents from the analysis rows on
their entities with detection signals and `responds_to` actions. Texts in `Texts.json` -> `manual`.

## Ideas, in the owner's order

1. Graphical setup editor (schema-driven forms in `--serve` mode).
2. Later: vendor photos (OneKey, Tapsigner, Keycard), tripwire refinements, a further audit of duplicated catalog entries.
3. See `REVIEW.md` for the open questions of the generic engine.

## Working rules

- Commit and push only when the owner asks.
- Keep answers and code lean; do not add features or documentation that were not asked for.
- New or changed behaviour gets a test.
