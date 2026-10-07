# Review: assessment, plan and open questions

Written before the restructuring on branch `generic-engine`; the final report is at the end.

## 1. Assessment

### Worth keeping

- **Ontology as schema.** `SetupOntology.schema.json` carries the class table (`x-classes`) and the reference marks (`x-ref`); the engine and the tests read them. This is the right pattern and is extended, not replaced.
- **Catalog shapes.** Threats with target, `applies_when` conditions, impacts as selector plus kind, base likelihood and modifiers; mechanisms with `addresses`, `present_when`, `applies_when`, `implicit_when`; principles refined by mechanisms; common-cause groups; rating scales and risk matrix in `Ratings.json`; report texts in `Texts.json`. All declarative and schema-validated.
- **The condition language** (`path`, `in`, `not_in`, `matches`, `not_matches`, `catalog.<column>`): small and sufficient.
- **`RecoveryActions.json`.** The composite actions (`R-ACCESS-WALLET` → `R-SATISFY-POLICY` → `R-ACCESS-QUORUM` → `R-ACCESS-SIGNER` → `R-ACCESS-SEED` → `R-UNLOCK-DEVICE` / `R-OBTAIN-SECRET` → `R-OBTAIN-ITEM-COPY` → `R-REACH-CARRIER`, `R-DECRYPT-WITH-ANY-KEY`, ...) with `any_of` / `all_of` / `k_of_n`, `foreach`, `when` and `requires` already *are* a declarative model of what spending needs. It was written as documentation and is never executed.
- **Modelling decisions** (people as carriers, rights versus delivered access, implicit default descriptors, concealed places, travel time): sound, and the fixture and 15 scenarios pin them down.
- **Tests**: 236, fixture plus metamorphic variants, premise-skips when a catalog changes, single-source tests. They are the regression oracle for the restructuring.
- **Report page**: four views, overrides with reasons, what-if on measures, focus mode. Kept; the data builder is adapted.
- **Lookup tables** with provenance per row.

### Knowledge hard-coded in the engine

| Where | What |
|---|---|
| `effects.hit()` | a per-class `if` ladder mapping (class, impact kind) to nine state sets (`lost`, `blocked`, `disclosed`, `controlled`, `tampered`, `secret_*`, `touched`) plus wallet flags |
| `effects.apply_impact()` | every impact selector (`contents`, `intrusion_contents`, `area_contents`, `knowledge`, `access`, `loaded_seeds`, `same_model_devices`, `same_vendor_devices`, `wallets`, `protects`) is Python; `wallets` also decides that a coordinator or a default descriptor is "replaceable" |
| `effects.Owner.obtain()` | how a person gets at a secret: backup items, memory, `encrypted_with`, seed on device behind PIN, descriptor on device or in a coordinator behind a password |
| `effects.attacker_secrets()` | the same knowledge again, from the attacker's side |
| `predicates.descriptor_known()`, `signers_known()`, `linking_descriptor()` | how a default descriptor follows from known keys and known descriptors |
| `effects.Evaluator.evaluate()`, `tier()` | which outcome follows from which situation; outcome names, the role `owner`, main versus tripwire |
| `model.Setup` | `_with_defaults` (repeats the schema defaults), `catalog_row` (which class joins which CSV), `has_descriptor`, `needs_registration`, `registration_support`, `quorum_covered`, `dependent_wallets`, `deps`, `quorum_minutes`, `is_main`, `memory_holders` |
| `predicates.py` | 15 structural predicates, all domain-specific |
| `analyze.py` | the literal catalog id `T-WALLET-TIMELOCK-LAPSE` chooses the barrier mechanisms |
| `rating.py` | `covers` semantics (`own`, `quorum`, `colocated_secrets`, `dependents`), `strength_from` |
| `loader.preflight()` | about a hundred lines of per-class rules (a mobile is carried, a memory backup sits in a person, a multi-signer wallet needs a descriptor, registration support per device...) |
| `report.py`, `report.template.html` | per-class subtitles, `secrets_in`, `coordinator_holds`; lanes, colours and glyphs per class in JavaScript |
| Schema | five near-identical backup item definitions; `storedIn` as a closed `oneOf` of location, bag, person; `encryptedWith` closed to seed or PIN |

### Duplicated knowledge

- How a secret is obtained: `Owner.obtain`, `attacker_secrets` and the `R-ACCESS-*` actions, three times, with no test that they agree.
- Schema `default`s and `Setup._with_defaults`.
- Three dependency walkers: `Setup.deps`, `Setup.dependent_wallets`, `rating.footprint`.
- `secret_roots` / `secret_locations`.
- Location kinds in the schema enum and in `LocationKinds.csv` (checked by a test, but still two places).

### Not general enough

- The set of classes is closed: a new kind of entity (password manager, node, safe as a container, exchange account) needs schema plus engine changes.
- Carriers are exactly location, bag and person; "to use X you need Y" exists three times (device PIN, coordinator password, encrypted item) as three code paths.
- No explicit threat actor with capabilities; sources are a flat enum, the actor's strength is folded into per-threat likelihoods and `applies_when` on catalog columns.
- Outcomes are fixed in code; send and receive paths are not separated in the outcomes.
- No deductive analysis, no per-person documents, no editor.

### Goals missing

1. Graphical editing (goal 1).
2. Deductive analysis (goal 2).
3. Threat-actor capabilities as data (goal 2).
4. Per-person manuals (goal 3).
5. A test that a new class or threat can be added through data alone.

### Rewrite or partial

**Partial rewrite of the core, the shell stays.** The pipeline (loader → setup graph → effects → rating → analyze → report) is fine, and the catalogs are largely the right data. What is replaced: `model.py`, `effects.py` and `predicates.py` become a generic graph (`graph.py`), a solver that executes the action catalog (`access.py`) and data-driven outcome rules (`outcomes.py`). `rating.py`, `analyze.py`, `feedback.py`, `measures.py`, the CLI and the report page are adapted. The scenarios and the test suite are the oracle: outcomes must stay the same unless a test is shown to encode an accident rather than a decision.

## 2. Plan and architecture

### The one idea

Everything the analysis needs to know about *how funds are reached* is one tree per wallet: what a person or an attacker must have, know or wait for. That tree is already written in `RecoveryActions.json`. The engine executes it, for

- the rightful people (inductive analysis: after a threat, can they still spend, when?),
- the attacker (with what leaked, can he spend, when?),
- the deductive analysis (minimal sets of parts whose loss or leak flips the answer),
- the manuals (the same tree rendered as checklists for one person).

The engine then knows only: entities with attributes and references, containers and places, status flags, agents with reach and knowledge, boolean/delay formulas, and conditions. Device types, location kinds, PINs, passphrases, descriptors are words in the data.

### Where each kind of knowledge lives (target)

| Knowledge | Home |
|---|---|
| Classes, parents, collections, attributes, references, defaults, per-class integrity (`if`/`then`) | `SetupOntology.schema.json` |
| Containers: which attribute places an entity, which classes are places, which class is a person-place | `x-classes` (`container`, `placed_by`) |
| Derived attributes used by actions (`copies`, `enclosing_bags`, `all_signers`, reverse references) | `AccessModel.json` → `derived` |
| What spending, obtaining a secret, unlocking a device need | `RecoveryActions.json` (executed) |
| Which atoms an agent satisfies (reach, intact, know, wait, guard bypass when controlled) | engine, generic |
| Impact selectors (`contents`, `knowledge`, `loaded_seeds`, ...) | `AccessModel.json` → `selectors` (six generic operations: self, located_in, reverse, peers, dependents, path) |
| Status flags and their meaning for intact/reach | `ThreatModelCommon.schema.json` (`impactKind`) |
| Which outcome follows from which facts | `Ratings.json` → `outcomes[].when` |
| Threats, mechanisms, actions, common cause, likelihood | the existing catalogs |
| Barrier against delayed policies | `Mechanisms.json` (`barrier_for`) instead of a threat id in code |
| Location kinds, devices, metal products | the CSV lookups |
| Report texts, per-class display (lane, colours, glyph) | `Texts.json` |

### Steps, in order

1. Assessment and plan (this file). Branch `generic-engine`.
2. **Access model.** Derived attributes and a solver that executes the action catalog for an agent (group of people, strict or relaxed; or the attacker) and returns the least delay. Replaces `Owner`, `attacker_secrets`, `descriptor_known`. Test: the solver agrees with the old evaluator on the fixture and the scenarios (then the old code is deleted).
3. **Status model and selectors.** Every entity carries status flags directly; impact selectors come from data. Deletes `hit()` and `apply_impact()` dispatch.
4. **Outcome rules in data**, `barrier_for`, send/receive path on threats.
5. **Single source for defaults and per-class rules**: defaults applied from the schema, `if`/`then` instead of preflight code where it fits.
6. **Extensibility test**: a temporary copy of the ontology and catalogs with a new class and a threat on it; the analysis runs and the new entity is hit, with no engine change.
7. **Deductive analysis**: minimal cut sets (loss) and minimal path sets (theft) per wallet and right, with the single threats that realise them; in the analysis file and a report tab.
8. **Manuals**: one HTML per person, generated from the access tree, the action texts, the practices and the responses; only what the person reaches or knows.
9. **Display tables to data**, then AGENTS.md, README, ARCHITECTURE.md.
10. Editor: schema-driven forms in the served report (generic by construction), if time remains.

### Assumptions taken

- Behaviour pinned by the existing tests is a decision unless shown otherwise; the restructuring must reproduce the fixture outcomes.
- The action catalog is allowed to grow derived-attribute paths and a `guards` mark; its texts double as manual steps.
- Threat actors stay sources with a description and a malicious flag in data; capability differences stay in per-threat likelihoods and `applies_when` (a separate actor-capability model is listed as an open question).
- Manuals are HTML (the diagram code of the report is reused), not PDF.

## 3. Open questions

Collected during the work; see the end of the final report.

## 4. Final report

Written when the work is done.
