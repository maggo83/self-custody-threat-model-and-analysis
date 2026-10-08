# Self-custody threat model and analysis

An automated threat analysis for Bitcoin self-custody setups, in the style of an FMEDA or HARA: inductive (every threat on every part) and deductive (which minimal sets of parts lose or leak the funds).

You describe a setup (people, places, devices, seeds, backups, wallets, coordinators, who may spend what) in one JSON file.
One command checks it, runs every threat of the catalog against every entity it can hit, and writes

- a raw analysis file with one line per threat and entity: likelihood, vulnerability, severity and risk, each with the reasoning behind it, and the cut and path sets per wallet,
- optionally an interactive report as a single offline HTML page, and
- optionally one manual per person: what they hold, how they spend or take over, what to check and what to do when something goes wrong, with only what that person needs to know.

The engine knows nothing about Bitcoin: classes, what spending needs, threats, measures and outcomes are data (see `ARCHITECTURE.md`).

The estimates in the catalogs are drafts. They are meant to be reviewed and changed by the owner of the setup; every rating can be overridden with a reason.

## Quick start

Needs Python 3.12 and `jsonschema` (`pip install jsonschema`).

```sh
python3 GenericThreatModelling/engine/threat_analysis.py SpecificThreatAnalysis/DummySetup.json --html
```

This writes `DummySetup.analysis.json` and `DummySetup.report.html` next to the setup. Useful options:

| Option | Effect |
|---|---|
| `-o FILE` | name of the analysis file |
| `--html [FILE]` | also write the interactive report |
| `--manuals [DIR]` | also write one standalone manual per person |
| `--images` | show pictures of signing devices in the report (see the notice in `Lookups/DeviceImages`) |
| `--serve [PORT]` | serve the report on `127.0.0.1` so that its "save overrides" button writes the overrides into the analysis file |
| `--feedback FILE` | merge overrides exported from the report |
| `--check-only` | validate the setup and the catalogs, then stop |

## The report

Five views of the same analysis:

- **Table (inductive)**: every threat on every entity with its three ratings, explanations, risk, and the reasoning chain. Ratings can be overridden in place, for a line, for a threat on all entities, or for all threats on one entity.
- **Setup diagram**: people, locations, devices, seeds, backups, wallets and the plan, with focus on what a person can reach or what a wallet or spending policy depends on. It can be colored by risk or by type.
- **Measures**: what each mechanism protects, and a what-if for adding or removing one.
- **Access**: who is meant to be able to spend which wallet, against what the setup actually delivers.
- **Fault trees (deductive)**: per wallet, the minimal sets of parts whose loss locks the rightful people out and whose leak lets an attacker spend, with the single threats that realise each set.

## How it is organised

- `SetupOntology.md` and `SetupOntology.schema.json`: the model of a setup. The schema is the single source of truth for the classes, their hierarchy, the references between them, defaults and per-class rules.
- `ARCHITECTURE.md`: where each kind of knowledge lives and how to extend the tool through data.
- `GenericThreatModelling/`: the catalogs and their schemas.
  - `Threats.json`: threats with targets, impacts, base likelihood and likelihood modifiers.
  - `Mechanisms.json`: structural and procedural measures and which threats they prevent, reduce or detect.
  - `RecoveryActions.json`: actions, including what spending a wallet or obtaining a secret requires; the engine executes them.
  - `AccessModel.json`: derived attributes, impact selectors, what an asset and an actor are, setup checks.
  - `Ratings.json`, `CommonCause.json`, `Texts.json`: scales, outcome rules and risk matrix, groups of threats that strike together, every text and display table.
  - `engine/`: the analysis engine, the report and the manual generators.
  - `tests/`: unit tests, a fixture setup, 15 scenarios from a hot wallet on a phone to nested bags at a trustee, and a test that adds a new class through data alone.
- `Lookups/`: catalogs of signing devices, metal backups and location kinds, and device pictures.
- `SpecificThreatAnalysis/`: a dummy setup. Analysis files and reports are generated and not kept in git; the overrides you give in a report are stored in the analysis file, so keep that file with your own setup.

## Tests

```sh
cd GenericThreatModelling
python3 -m unittest discover -s tests
```

`tests/scenarios/generate.py` rebuilds the analysis and report of every scenario.

## License

[Grug 2-Clause License](LICENSE). The device pictures in `Lookups/DeviceImages` are third-party material under their own license; see the [notice](Lookups/DeviceImages/NOTICE.md).
