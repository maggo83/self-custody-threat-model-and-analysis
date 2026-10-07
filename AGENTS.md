# Notes for working on this repository

Read `README.md` first for what the tool does and how to run it. This file holds what is not obvious from the code.

## Commands

```sh
# tests (about 50 s); run from GenericThreatModelling
cd GenericThreatModelling && python3 -m unittest discover -s tests

# regenerate the dummy analysis and report (run from the repository root)
python3 GenericThreatModelling/engine/threat_analysis.py SpecificThreatAnalysis/DummySetup.json \
  -o SpecificThreatAnalysis/DummySetup.analysis.json --html --images

# regenerate the 15 scenario reports
cd GenericThreatModelling/tests/scenarios && python3 generate.py
```

Analysis files and reports (`*.analysis.json`, `*.report.html`, `tests/scenarios/index.html`) are generated and ignored by git. Regenerate them to look at a change in `engine/report.template.html`, the catalogs or the engine; run the tests first.
Python 3.12, standard library plus `jsonschema` (Draft 2020-12), tests with `unittest` only.

## Principle: one source per fact

Duplicated knowledge drifts, so each fact has one home and the rest is derived or checked by a test (`SingleSource` in `tests/test_engine.py`).

| Fact | Home |
|---|---|
| Classes, parents, abstract and nested flags, collection names, "credential" secrets | `x-classes` table in `SetupOntology.schema.json`, read by `engine/ontology.py` |
| Which class a reference must point to | `x-ref` marks in `SetupOntology.schema.json`, checked by `loader.references()` |
| Threat categories, sources (and which are malicious), phases, impact selectors and kinds (and which leak) | `$defs` of `GenericThreatModelling/ThreatModelCommon.schema.json`, read by `engine/vocab.py` |
| Base likelihood and its modifiers | inside each threat in `Threats.json`, defaults per category in `category_likelihood` |
| Location kinds, which are remote | `Lookups/LocationKinds.csv` |
| Outcomes and their severity | `Ratings.json`; `Texts.json` must have the same keys |

When adding a class, enum value, selector, outcome or category: change the home, then let the tests tell what else must follow
(diagram in `SetupOntology.md`, report tables for colors and icons, texts).
Prefer attributes and conditions in the catalogs over new special cases in the engine. Merge threats only if they are addressed
by the same mechanisms; identical effects alone are not a reason (send, receive and change address threats stay separate).

## Engine

Pipeline: `loader` (catalogs, schema validation, preflight) -> `model.Setup` (the setup as a graph) -> `effects` (state after a threat,
who can still spend, what an attacker can do, outcomes) -> `rating` (likelihood, vulnerability from mechanisms, severity, risk) -> `analyze`
(all threats on all entities, overrides, what-if) -> `report` plus `report.template.html` (one offline page, data inserted at `__DATA__`).
Others: `measures` (what-if for mechanisms), `feedback` (overrides), `predicates` (named checks used by catalogs), `ontology`, `vocab`,
`threat_analysis` (CLI, `--serve` local save server).

Modelling decisions that are easy to get wrong:

- **Devices:** `Device` is abstract with `SigningDevice` (seeds and descriptors, never hosts a coordinator) and `ComputingDevice`
  (mobile, laptop, desktop; hosts coordinators, can hold seeds as a hot wallet; attribute `online`, default true).
  A coordinator must `runs_on` a computing device. A controlled computing device also controls the coordinator on it.
- **People as carriers:** `stored_in {person}` puts an item in the person's memory or on them (internally a virtual place `person:<id>`).
  Death, incapacity and amnesia wipe memory contents, never devices carried. Memory backups must be stored in a person;
  a mobile is always carried, a desktop never.
- **Access rights:** `may_spend` on a person says who may spend which wallet and after how long, alone or with others.
  Outcomes compare this with what the setup delivers. If everybody who may spend a main wallet is gone, there is no loss outcome;
  if one is alive and cannot reach it, there is.
- **Overrides:** an override sets a rating for a line, for a threat on all entities, or for all threats on one entity (line wins over
  threat over entity), or answers a question for the owners. A reason is required. Overrides live in the analysis file.
- **Implicit measures:** a procedural mechanism can count as present because of how an entity is used (`implicit_when`), without a practice.

## Report page

Diagram: people, locations, secrets, wallets and plan in lanes. Devices and people are boxes that hold what is in them
(software, seeds, descriptors, backups) in sub-lanes; lanes nobody uses are not drawn. Focus mode starts only from the focus list;
inside it a click on a person, wallet or one of several policies moves the focus, a click on anything outside the focus ends it.
"Color by risk" can be switched to a color per type, where backups are a darker shade of what they hold.
The page has JS tables per class (colors, icons); a test fails if a class is missing.

## Ideas, in the owner's order

1. Graphical setup editor.
2. Deductive (fault tree) analysis, after the inductive one.
3. Later: vendor photos (OneKey, Tapsigner, Keycard), tripwire refinements, a further audit of duplicated catalog entries.

## Working rules

- Commit and push only when the owner asks.
- Keep answers and code lean; do not add features or documentation that were not asked for.
- New or changed behaviour gets a test.
