# Architecture: where knowledge lives and how to extend it

The engine knows only abstract things: entities with attributes and references, containers and places, status flags,
agents with reach and knowledge, trees of requirements with delays, and conditions. Everything about Bitcoin custody
(devices, seeds, PINs, descriptors, bags, what spending needs) is data. This note says which file holds which kind of
knowledge, how the engine uses it, and what to touch to extend the tool.

## Pipeline

```
loader ─ reads the schemas, catalogs and lookups, validates the setup, runs the declared checks
graph  ─ Setup: entities, containers, places, reach, derived attributes, expression language
access ─ builds the access trees from RecoveryActions.json and evaluates them for agents (people, attacker)
outcomes ─ facts about a state (who can spend, when, what the attacker can do) → outcome rules → outcomes
rating ─ likelihood, vulnerability (mechanisms), severity, risk
analyze ─ every threat on every entity it can hit, overrides, what-if, deductive section
deductive ─ minimal cut sets (loss) and path sets (theft) with the threats that realise them
report / manuals ─ the offline page and one HTML per person
```

A row of the analysis is: a threat applied to an entity (or a common-cause group) gives a `State` (status flags on
entities, from the threat's impacts and the selectors); the `Evaluator` computes facts for each main wallet in that
state; the `outcome_rules` map facts to outcomes; the rating turns them into numbers.

## Knowledge map

| Knowledge | File | Read by |
|---|---|---|
| Classes, hierarchy, collections, attributes, references (`x-ref`), defaults, per-class rules (`if`/`then` + `x-message`) | `SetupOntology.schema.json` | `ontology`, `loader`, `graph.apply_defaults` |
| Class flags: `abstract`, `nested`, `singleton`, `place`, `placed_by`, `access_by`, `near`, `credential`, `information`, `active`, `inherits_status`, `privacy`, `catalog` | `x-classes` in the schema | `graph.flag`, `access` |
| Derived attributes (reverse references, closures, unions; e.g. `Seed.copies`, `Device.enclosing_bags`, `Wallet.all_signers`) | `AccessModel.json` → `derived` | `graph.compute_derived` |
| What spending, satisfying a policy, obtaining a secret, unlocking a device, knowing a descriptor need | `RecoveryActions.json` (`requires`, `steps`, `combinator`, `k`, `foreach`, `when`, `optional`, `guards`, `for`) | `access.tree` |
| Which action is the goal for spend / policy / descriptor / know | `AccessModel.json` → `goals` | `access.spend_tree`, `knows`, `descriptor_known` |
| What an asset is (main wallets, policies, quorum), what an actor is (rights, co-signers, delay, owner role), travel | `AccessModel.json` → `asset`, `actor`, `travel` | `outcomes`, `rating.quorum_minutes`, `loader.preflight` |
| Impact selectors (`contents`, `knowledge`, `loaded_seeds`, `coordinated_wallets`, ...) | `AccessModel.json` → `selectors` | `access.apply_impact` via `graph.select` |
| Which statuses each class takes when a probe "loses" or "leaks" it (for the redundancy margin) | `AccessModel.json` → `margin_probes` | `outcomes.Evaluator` |
| Setup checks beyond the schema (errors and warnings with `{path}` placeholders) | `AccessModel.json` → `checks` | `loader.preflight` |
| Status kinds, which leak, threat categories, sources, phases | `ThreatModelCommon.schema.json` `$defs` | `vocab` |
| Threats: target class, `applies_when`, impacts (selector + kind, `unless`/`only`), likelihood and modifiers | `Threats.json` | `analyze.instances`, `rating.likelihood` |
| Mechanisms: structural (`present_when`, `strength_from`) or procedural (practice or `implicit_when`), what they cover, `barrier_for`, `weakened_when`, `signal`, `procedure` | `Mechanisms.json` | `rating.mechanism_instances`, `vulnerability`, `manuals` |
| Outcomes and severities, outcome rules (facts → outcome, `unless_emitted`), `outcome_by_asset`, exploit order, `after_delay`, travel budget | `Ratings.json` | `outcomes.Evaluator.evaluate`, `rating.severity` |
| Threats that strike together | `CommonCause.json` | `analyze` |
| Location kinds (remote or not), signing devices, metal backups, device pictures | `Lookups/*.csv` | `graph.catalog_row` via the `catalog` flag |
| Every text the user sees: class names, effects, outcomes, lanes/colours/icons (`display`), subtitles, manual texts | `Texts.json` | `report`, `manuals`; the template has no literals |

A test in `tests/test_engine.py` (`SingleSource`) fails when two of these drift apart; `tests/test_extensibility.py`
proves that a new class with its own action and threat works through data alone (`CUSTODY_DATA_ROOT` points the engine
at a copy of the knowledge files).

## The expression language

Conditions and paths are small JSON objects evaluated by `graph.evaluate`/`graph.condition`:

- Path: `"copies[].place"`, `"$device.pin"`, `"catalog.remote"`, pseudo attributes `class` (with ancestors), `root`,
  `place`, `container`. A path without `$` starts at `$self`; `[]` is documentation, lists are always flattened.
- Condition: `{"path": ..., "in" | "not_in" | "eq" | "neq" | "matches" | "contains" | "intersects" | "disjoint" | "gt" | "ge" | "lt" | "le" | "nonempty": ...}`,
  with `"count": true` to compare the number of values.
- Combinators: `{"all": [...]}`, `{"any": [...]}`, `{"not": ...}`, `{"forall" | "exists": <class or path>, "as": "$x", "where": ...}`.
- Capability: `{"can": {"agent": "everyone" | "attacker" | {"person": "$p"}, "action": "R-...", "args": {...}}}`.
- A bare string is a fact name (in outcome rules) or a path whose truthiness is tested.

Derived attributes use `path`, `select` (+ `where`, `yield`), `union`, `containers`, `roots_of`, `reach`,
`dependents`, `dependencies`, `inside`, `value`; `single: true` returns a scalar.

## Access trees

An action is a node: atoms it `requires` (`reach`, `intact`, `known`, `wait`, `have`) and `steps` (child actions) joined
by `all_of`, `any_of` or `k_of_n`. A step may be `optional` (a check that does not gate access), may `guard` an entity
(if the agent *controls* that entity the step is bypassed; this is how a stolen device with a known PIN works), may
repeat `foreach` a derived list, and may be `for: attacker` only. Agents answer atoms from the state:

- People (a group, strict or relaxed): reach = the entity is intact and at a place one of them can reach (memory is a
  place `person:<id>`, so knowledge is reach of the carrier); `known` atoms are never satisfied (they describe what has
  already leaked to the attacker); wait = the delay; strict counts `unavailable` parts as missing.
- Attacker: reach = disclosed, or commands the entity (controlled, or tampered and `active`); known = disclosed and
  intact; commands bypass guards. Leaks propagate to entities with `inherits_status` placed in the hit entity.

The same trees serve the inductive analysis (value for the people, value for the attacker), the deductive analysis
(cut and path sets over the atoms) and the manuals (rendered as checklists pruned to what a group can do).

## How to extend

| You want to | Touch |
|---|---|
| A new entity class | `x-classes` + `$defs` + a collection in `SetupOntology.schema.json`; `Texts.json` → `classes` and `display`; derived attributes and, if it takes part in access, an action in `RecoveryActions.json` and a step that uses it (see `test_extensibility.py` for a complete example) |
| A new attribute | the class `$defs`; a default there if it has one; a condition somewhere that uses it |
| A new threat | `Threats.json`; impacts name a selector and a status kind; detection/response in `Mechanisms.json`/`RecoveryActions.json` |
| A new mechanism | `Mechanisms.json`; `present_when`/`strength_from` or a `procedure` with a `schedule`; `addresses` |
| A new outcome | `Ratings.json` → `outcomes` and a rule in `outcome_rules`; `Texts.json` → `outcomes` |
| A new way to spend or recover | an action in `RecoveryActions.json`; the solver and the manuals pick it up |
| A new impact selector | `AccessModel.json` → `selectors` using the selector forms (`self`, `placed_in`, `path`, `peers`) |
| A new setup rule | `if`/`then` with `x-message` in the schema when it is one entity, otherwise `AccessModel.json` → `checks` |
| A new fact for outcome rules | this is the one place that needs code: `outcomes.Evaluator.facts` |

Rules of thumb: when the engine would need to know a class or entity name, put the knowledge into one of the files above
instead. Let the tests say what else must follow; keep every new behaviour pinned by a test.

## What still lives in code

- The facts computed for the outcome rules (`outcomes.facts`): spendable within rights, delayed, attacker tiers,
  privacy, margin, and the redundancy profile; they are generic in the sense that they only use the access trees.
- The rights model: that an actor has rights with co-signers, a delay and assets, and that outcomes compare them with
  what the setup delivers (field names come from `AccessModel.actor`).
- The travel measure (`strength_from: quorum_travel_minutes`) and the preflight checks for practices, travel pairs and
  contradicting delays.
- The lanes of the diagram (people, things, secrets, wallets, plan) are a layout decision in the template; which class
  goes where is in `Texts.json` → `display`.
