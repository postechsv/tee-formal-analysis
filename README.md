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
| `tools/` | Build and transformation tools: `gen-dmc.py` (DM-Check build), `gen-maude2lean.py`, `ghost.py`, `ta2imp.py` (C TA to TEE-IMP), `tee-build.py` (case-study build), `gen-docs.py`, the spec test runners. |
| `ghost/` | Ghost files composed with the spec rules (`make GHOST=...`). |
| `mk/features.mk` | Feature groups of the specification that a build can drop. |
| `experiments/` | Scripts that run the experiments of the paper tables and summarize their logs. |
| `results/paper/` | Raw logs of the paper experiments. Other output under `results/` is not tracked. |
| `docs/` | Inputs of the documentation site, notes, and the paper. |

## Requirements

- Maude 3
- GNU Make, Python 3
- GNU parallel (for `experiments/run-exp`)

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
make NAME=t GHOST=ghost/overwrite.maude DMC=1
make docs                    # documentation site of the spec in build/docs
```

`SPEC=../tee-formal-spec` builds a sibling checkout of the specification instead of the submodule.

## MQT-TZ

`case-studies/mqttz/mqttz.toml` describes the system: the API feature groups of the spec it uses and
the ghost state its LTL propositions read (`running`, `state-changed` of the TA), which the spec
itself does not have.  How it is analyzed is chosen when it is built:

```bash
make mqttz                   # build/mqttz: the spec with those features and ghosts, and main.maude
make mqttz INVISIBLE=1       # build/mqttz-inv: the same with the invisible-transition reduction
make mqttz MODE=dmc          # build/mqttz-dmc: the DM-Check build
```

The TA programs are translated from `ta/hot_cache_ta.c`, the C source as published, by
`tools/ta2imp.py` into `build/<name>/ta/broker-ta.maude`: `mqttzTA` from the source with
`ta/model.patch` (the modeling changes of the C code), and `mqttzTaPatched` with `ta/fix.patch` on
top (the code-level fix).  How C maps to the model (types, buffer sizes, TEE_Param memory
references, dropped logging and timing calls, ...) is declared in the `[ta.broker]` table of the
manifest.  `build/<name>/model.maude` loads the built spec, the model files and the TAs, and
`build/<name>/main.maude` adds `case-studies/mqttz/cmd/main.maude` (the scenarios, the threats and
the LTL properties).

`experiments/run PROP THREAT [-patch] RED` writes one model-checking run (Maude file and log) on
`build/mqttz-inv`, and `experiments/run-exp table2|table3` runs a whole table.
