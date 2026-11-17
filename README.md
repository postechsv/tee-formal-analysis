# TEE Formal Analysis

Formal analyses of trusted applications on top of the [TEE formal specification](https://github.com/postechsv/tee-formal-spec)
(a Maude model of the GlobalPlatform TEE Internal Core API), and the tools that transform that
specification for an analysis.  The specification is a separate repository: each analysis names the
revision it uses, which is fetched and built with the specification's own Makefile.

## Publications

- Geunyeol Yu, Seunghyun Chae, Kyungmin Bae, Sungkun Moon, Siheung Kim.
  [Formal Specification of Trusted Execution Environment APIs and Model Checking of Trusted Applications](https://doi.org/10.1145/3837076).
  Formal Aspects of Computing, January 2026. The journal version of the FASE 2024 paper.
- Geunyeol Yu, Seunghyun Chae, Kyungmin Bae, Sungkun Moon.
  [Formal Specification of Trusted Execution Environment APIs](https://doi.org/10.1007/978-3-031-57259-3_5).
  FASE 2024, LNCS, Springer.

## Layout

| Path | Contents |
| --- | --- |
| `mqttz/` | The MQT-TZ case study: `Makefile`, `model-checking.toml` (the analysis of the papers: the system and how it is analyzed), `core/` (the model files written by hand), `scripts/` (the experiments of Tables 2 and 3 of the FASE 2024 paper, Tables 10 and 11 of the FAC paper), `models/` (the built models, not tracked). See [mqttz/README.md](mqttz/README.md). |
| `kmgk/` | The KMGK case study: `Makefile`, `model-checking.toml` (the session checks), `dmc.toml` (its DM-Check build, with the DM-Check directives of the spec), `core/` (the model files written by hand). See [kmgk/README.md](kmgk/README.md). |
| `optee-keymint/` | The instance lifetime of the Google OP-TEE KeyMint TA: the instance model (S1–S6), the Rust TA and client, and the scripts that check the model against the real TA. It has its own pipeline and is not built by `tee-build.py`. See [optee-keymint/README.md](optee-keymint/README.md). |
| `tools/build/` | `tee-build.py` (builds an analysis `C/A.toml` of a case study into its output directory) and `transform.mk` (the transforms of a spec build), with `drop-rules.py`, `drop-class-attribute.py`, `ghost.py` and `gen-invisible.py`. |
| `tools/lang-preprocess.py` | Preprocesses the C source of a TA or RA into the programs of the model. |
| `tools/dmc/` | `gen-dmc.py` (the DM-Check build of the spec) and its Maude libraries in `lib/`. |
| `tools/gen-maude2lean.py` | Generates the maude2lean build from the DM-Check build. |
| `tools/ce-viewer/` | `ce-viewer.html` (the viewer of counterexample logs) and `path2ce.py` (turns the path of a `show path` into a log the viewer loads). |
| `build/` | Cache (not tracked): the fetched spec revisions (`build/spec/`) and the transformed builds (`build/C-A/`). |

The feature groups and test suites of the specification are in the specification repository.
Checks and scripts that are not part of an analysis (the paper-anchor check of the specification,
and the export of the counterexample paths of KMGK) are in `tee-formal-analysis-misc`, a separate
repository.

## Contents

```
tee-formal-analysis/
├── README.md                       This guide
├── LICENSE                         License of this repository (GPL-3.0)
├── config.mk                       Personal settings, gitignored: MAUDE and MAUDE2LEAN paths
├── mqttz/                          The MQT-TZ case study (details in mqttz/README.md)
│   ├── Makefile                    make <analysis>: builds models/<analysis>
│   ├── model-checking.toml         The analysis: the system (spec revision, TA and RA preprocessing),
│   │                               the dropped rules and attribute, the ghost and invisible rules
│   ├── core/                       The model files written by hand: system, TA and RA (C sources and
│   │                               patches), environment, scenarios, threats, properties, tests
│   ├── scripts/                    Paper Table 2 and Table 3: run, run-exp, gen-report, gen-table
│   ├── models/                     Built by make, gitignored: one model per analysis
│   └── output/                     Created by the scripts, gitignored
├── kmgk/                           The KMGK case study (details in kmgk/README.md)
│   ├── Makefile                    make <analysis>: builds models/<analysis>
│   ├── model-checking.toml         The analysis of the session checks
│   ├── dmc.toml                    The DM-Check build, with the DM-Check directives of the spec
│   ├── core/                       The model files written by hand: the TAs (C sources and patches),
│   │                               the RA, the scenarios and the searches
│   ├── models/, output/            Built by make and export-paths, gitignored
├── optee-keymint/                  The OP-TEE KeyMint instance model (details in optee-keymint/README.md)
│   ├── keymint-instance.maude      The instance model
│   ├── keymint-scenarios.maude     Scenarios S1–S6
│   ├── rust/                       The Rust TA and client, and the globals of the instance model
│   └── scripts/                    The pipeline: path export, operation traces, transition coverage,
│                                   and the check against the real TA
├── tools/
│   ├── build/
│   │   ├── tee-build.py            Build an analysis C/A.toml of a case study into its output directory
│   │   ├── transform.mk            The transforms of a spec build (drop, ghost, invisible, DM-Check, maude2lean)
│   │   ├── drop-rules.py           Remove the rules of the spec that an analysis leaves out
│   │   ├── drop-class-attribute.py Drop a class attribute from rule left-hand sides
│   │   ├── ghost.py                Compose ghost state with the spec rules
│   │   └── gen-invisible.py        Generate the invisible-transition reduction
│   ├── lang-preprocess.py          Preprocess the C source of a TA or RA into the programs of the model
│   ├── gen-maude2lean.py           Generate the maude2lean build from the DM-Check build
│   ├── ce-viewer/                  ce-viewer.html and path2ce.py (counterexample viewer)
│   └── dmc/
│       ├── gen-dmc.py              Generate the DM-Check build of the spec
│       └── lib/                    Maude libraries of gen-dmc
└── build/                          Cache, gitignored: fetched spec revisions (build/spec/) and
                                    transformed builds (build/C-A/)
```

## Case studies and analyses

A case study is a directory `C/` (`mqttz/`, `kmgk/`) with its own `Makefile`, the model files written
by hand in `C/core/`, and one file `C/A.toml` per analysis `A`.  An analysis file is a TOML file with a
`[spec]` table, and it is standalone.  It says what the analyzed system is:

- `[spec]`: the specification, as `repo` and `rev` (a commit, branch or tag), or as `checkout` (a
  checkout relative to `C/`), with `without` (modules that the spec build leaves out) and
  `[spec.features]` (`FEATURE = 0` or `1`, overriding the defaults of the spec's `features.mk`);
- `[ta.KEY]` and `[ra.KEY]`: the TAs and RAs, preprocessed from their C sources by
  `tools/lang-preprocess.py`.

and how it is analyzed:

- `mode`: `plain`, `dmc` (the DM-Check build) or `m2l` (the maude2lean build);
- `output`: the directory of the built model, default `models/A`;
- `m2l-eq` (`make M2L_EQ=0`) and `check` (`make check-dmc` and `make check-m2l`);
- `ghost-modules` (ghost modules composed with the spec rules), `drop-rules` (rule labels that the
  analysis leaves out), and the tables `[drop-class-attribute]`, `[ghost]`, `[invisible]` and `[dmc]`
  (the directives of the DM-Check transform, needed by `mode = "dmc"` and `"m2l"`).

The paths in the file are relative to `C/`.  `tools/build/tee-build.py` reads the file; see its
docstring for every key.  `make A` in `C/` (or `tools/build/tee-build.py C A`) builds the analysis:

1. The revision of `[spec]` is fetched into `build/spec/<commit>/`.  A branch or a tag is fetched
   again at every build; a commit is fetched once.
2. The specification is built with its Makefile, with the feature settings of the analysis.  The
   transforms of the analysis are applied to it by `tools/build/transform.mk`, in `build/C-A/`.
   The cache is kept, and the transform tables are written to `build/C-A/A.toml`.
3. The output directory (`C/models/A/` by default) is written from scratch with the final model,
   which loads on its own: `src/` (the transformed specification), `lang/` (the language files of
   the spec, when it has them), `core/` (a copy of `C/core/`), `ta/` and `ra/` (the preprocessed TAs
   and RAs, when the analysis has them), `model.maude` (which loads all of them), and `main.maude` (which adds
   `core/cmd/main.maude`, the entry module of the analyses).

`make A SPEC=DIR` builds the analysis on a spec checkout instead of the revision of `[spec]`.

## Requirements

- Maude 3
- Python 3.11 or later (for `tomllib`), GNU Make, git
- maude2lean, only for the `m2l` mode and `make lean`

The personal settings go in `config.mk` at the repository root (gitignored):

```make
MAUDE := /path/to/maude
MAUDE2LEAN := /path/to/maude2lean   # only for the m2l mode and make lean
```

## Getting started

```bash
cd mqttz
make model-checking          # mqttz/models/model-checking: the model of the paper experiments
make                         # every analysis of mqttz
make help                    # the analyses
```

`mqttz/README.md` describes the experiments (`scripts/run-exp table2`, `table3`).  KMGK is built the
same way, in `kmgk/`:

```bash
cd kmgk
make model-checking          # kmgk/models/model-checking
```

The DM-Check build of KMGK is the analysis `dmc` of its case study, so it is built from its analysis
file (`mode = "dmc"`, with the `[dmc]` directives) and not with settings on the command line:

```bash
cd kmgk
make dmc                     # kmgk/models/dmc: the DM-Check build of dmc.toml
```

The build of a specification checkout alone, with its test suites, takes no case study.  From the
repository root (`build/t`, with the settings cached there):

```bash
make -f tools/build/transform.mk SPEC=../tee-formal-spec NAME=t CRYPTO=0 test
```
