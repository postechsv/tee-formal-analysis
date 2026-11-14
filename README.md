# TEE Formal Analysis

Formal analyses of trusted applications on top of the [TEE formal specification](https://github.com/kkw423/tee-formal-spec)
(a Maude model of the GlobalPlatform TEE Internal Core API), and the tools that build and transform
that specification.

## Layout

| Path | Contents |
| --- | --- |
| `spec/` | The specification, as a git submodule of `tee-formal-spec` (pinned commit). |
| `case-studies/mqttz/` | The MQT-TZ broker: `mqttz.toml` (the manifest), `ta/` (the upstream C TA, its modeling patch, the fix patch, the TEE-IMP dispatcher and the template), `ra/`, `env/` (broker, clients, entities, TA constants), `system.maude`, `scenarios/`, `properties/` (LTL), `threats/`, `tests/`, `cmd/` (entry modules of the analyses). |
| `case-studies/kmgk/` | The KMGK benchmark. Not yet ported to the current specification. |
| `tools/build/` | Spec and case-study build: `tee-build.py` (case-study build), `select-main.awk`, `ghost.py`, `drop-condition.py`, `gen-invisible.py`. |
| `tools/ta2imp/` | `ta2imp.py` (C TA to TEE-IMP); `translate.py`, the translator of the original artifact (not used by `ta2imp.py`). |
| `tools/dmc/`, `tools/lean/` | `gen-dmc.py` (DM-Check build) and its Maude libraries; `gen-maude2lean.py`. |
| `tools/test/` | The spec test runners. |
| `tools/docs/` | `gen-docs.py` (documentation site), `gen-examples.py`, and their inputs in `input/`. |
| `tools/experiments/` | Scripts that run the experiments of the paper (Table 2 and Table 3) and summarize their logs. |
| `features.mk` | Feature groups of the specification that a build can drop. |
| `results/` | Output of the experiments (not tracked). |
| `paper.pdf` | The paper. |

## Contents

```
tee-formal-analysis/
├── Makefile                        Entry point: build the spec, its tests, case studies, docs
├── features.mk                     Feature groups of the spec a build can drop (was mk/)
├── config.mk                       Personal settings, gitignored: MAUDE, MAUDE2LEAN paths
├── README.md                       This guide
├── LICENSE                         License of this artifact (GPL-3.0)
├── paper.pdf                       The paper (at the root, as in the original artifact)
├── spec/                           The TEE formal specification (git submodule tee-formal-spec)
├── case-studies/
│   ├── mqttz/                      The MQT-TZ broker
│   │   ├── mqttz.toml              Manifest: ghosts, invisible rules, TA translation
│   │   ├── main.maude              Loads the model files
│   │   ├── system.maude            Module MQTTZ: all entity behaviors, the RA and the TA
│   │   ├── ta/                     The trusted application
│   │   │   ├── hot_cache_ta.c      Upstream C source, as published
│   │   │   ├── model.patch         Modeling changes to the C code
│   │   │   ├── fix.patch           Code-level fix (mqttzTaPatched)
│   │   │   ├── main.imp            void main() dispatcher 
│   │   │   └── template.maude      Template of broker-ta.maude
│   │   ├── ra/
│   │   │   └── broker-ra.maude     RA programs mqttzHost and mqttzHostPatched
│   │   ├── env/                    The other participants
│   │   │   ├── base.maude          Keys, topics, subscriptions
│   │   │   ├── entity.maude        Abstract entity and client
│   │   │   ├── client.maude        Publishers and subscribers
│   │   │   ├── broker.maude        Broker: storing and re-encrypting messages
│   │   │   └── ta-data.maude       TA constants (TA_* macros of hot_cache_ta.h)
│   │   ├── scenarios/              Initial states
│   │   │   ├── aux.maude           Initialization functions (clients, keys)
│   │   │   ├── base.maude          The paper scenario: 2 publishers, 2 subscribers, 1 broker,
│   │   │   │                       2 topics
│   │   │   └── inv.maude           Smaller scenarios scenario-inv1..4
│   │   ├── threats/
│   │   │   ├── main.maude          Loads the threats
│   │   │   ├── oom.maude           Out-of-memory threat (OOM-THREAT)
│   │   │   └── msg.maude           Message intruder (MSG-THREAT, initInt)
│   │   ├── properties/
│   │   │   ├── propositions.maude  State propositions (read the ghost state)
│   │   │   └── properties.maude    LTL properties p1–p6
│   │   ├── cmd/                    Entry modules of the analyses (ANALYSIS-CMD)
│   │   │   ├── main.maude          system + scenarios/base + threats + properties
│   │   │   └── inv.maude           system + scenarios/inv + threats + properties
│   │   └── tests/
│   │       ├── main.maude          Test driver
│   │       └── cases/              Calls of the TA, per API group: transient, persistent,
│   │                               data-stream, generic, cryptographic
│   └── kmgk/                       The KMGK benchmark (not yet ported to the current spec)
├── tools/
│   ├── build/
│   │   ├── tee-build.py            Build a case study from its .toml manifest
│   │   ├── select-main.awk         Filter src/main.maude for a feature configuration
│   │   ├── ghost.py                Compose ghost state with the spec rules
│   │   ├── drop-condition.py       Drop rule conditions
│   │   └── gen-invisible.py        Generate the invisible-transition reduction
│   ├── ta2imp/
│   │   ├── ta2imp.py               Translate a C trusted application into TEE-IMP
│   │   └── translate.py            Translator of the original artifact (not used by ta2imp.py)
│   ├── dmc/
│   │   ├── gen-dmc.py              Generate the DM-Check build of the spec
│   │   └── lib/                    Maude libraries of gen-dmc (was dmc-lib/)
│   ├── lean/
│   │   └── gen-maude2lean.py       Generate the maude2lean build from the DMC build
│   ├── test/
│   │   ├── run-api-suite.py        API-level black-box test runner
│   │   └── run-checks.py           search/red check runner
│   ├── docs/
│   │   ├── gen-docs.py             Build the documentation site
│   │   ├── gen-examples.py         Generate input/examples.json
│   │   └── input/
│   │       ├── overview.html       Hand-written body of index.html
│   │       ├── seeds/              Searches for rules the tests never reach (was example-seeds/)
│   │       └── examples.json       Verified examples (committed: CI has no Maude)
│   └── experiments/                Paper Table 2 and Table 3 (was experiments/)
│       ├── run-exp                 run-exp table2|table3 [-non-parallel]
│       ├── run                     run PROP THREAT [-patch] [MAUDE_DIR] [LOG_DIR] [-silent]
│       ├── gen-report              Logs of a table → table<i>-report.csv
│       └── gen-table               Report → table<i>.html
├── .github/workflows/docs.yml      Build the docs site and deploy it to GitHub Pages
├── build/                          Created by make, gitignored
└── results/                        Created by the experiments, gitignored (empty)
```

## Requirements

- Maude 3
- GNU Make, Python 3
- GNU parallel (for `tools/experiments/run-exp`)

Set the Maude binary in `config.mk` (gitignored) at the repository root:

```make
MAUDE := /path/to/maude
MAUDE2LEAN := /path/to/maude2lean   # only for make lean
```

## Getting started

```bash
git clone --recurse-submodules <this repository>
make test                    # build the spec into build/default and run its test suites
make help                    # features, settings and targets
make NAME=t CRYPTO=0 test    # a build without the cryptographic operation API
make NAME=t DMC=1            # the DM-Check build
make NAME=t GHOST=FILE.maude DMC=1  # compose a ghost module with the spec rules
make docs                    # documentation site of the spec in build/docs
```

`SPEC=../tee-formal-spec` builds a sibling checkout of the specification instead of the submodule.

## MQT-TZ

`case-studies/mqttz/mqttz.toml` describes the system: the ghost state its LTL propositions read
(`running` of the TA), which the spec itself does not have, and the TA translation.  Every API
feature group of the spec is on.  How it is analyzed is chosen when it is built:

```bash
make mqttz                   # build/mqttz: the spec with the ghosts, and main.maude
make mqttz INVISIBLE=1       # build/mqttz-inv: the same with the invisible-transition reduction
make mqttz MODE=dmc          # build/mqttz-dmc: the DM-Check build
```

The TA programs are translated from `ta/hot_cache_ta.c`, the C source as published, by
`tools/ta2imp/ta2imp.py` into `build/<name>/ta/broker-ta.maude`: `mqttzTA` from the source with
`ta/model.patch` (the modeling changes of the C code), and `mqttzTaPatched` with `ta/fix.patch` on
top (the code-level fix).  What the model leaves out or changes in the C code (logging, timing,
buffer sizes, the split of the TEE_Param memory references, ...) is in `ta/model.patch`; the
`[ta.broker]` table of the manifest only says what to translate.  `build/<name>/model.maude` loads the built spec, the model files and the TAs, and
`build/<name>/main.maude` adds `case-studies/mqttz/cmd/main.maude` (the scenarios, the threats and
the LTL properties).

## Experiments of the paper

Table 2 of the paper model-checks the properties p1–p6 of the original MQT-TZ RA and TA under no
threat, the out-of-memory threat and the message intruder; Table 3 does the same for the patched
RA and TA.  Both run on `build/mqttz-inv`:

```bash
make mqttz INVISIBLE=1
tools/experiments/run-exp table2             # results/table2/{maude-files,logs}, in parallel
tools/experiments/run-exp table3 -non-parallel
cd results
../tools/experiments/gen-report table2       # table2-report.csv
../tools/experiments/gen-table table2-report.csv   # table2.html
```

`tools/experiments/run PROP THREAT [-patch] [MAUDE_DIR] [LOG_DIR] [-silent]` writes and runs one of
them (PROP `p1`..`p6`, THREAT `non`, `oom` or `msg`, `-patch` for the patched programs).
