# TEE Formal Analysis

Formal analyses of trusted applications on top of the [TEE formal specification](https://github.com/kkw423/tee-formal-spec)
(a Maude model of the GlobalPlatform TEE Internal Core API), and the tools that transform that
specification for an analysis.  The specification is a separate repository: each case study names
the revision it uses, which is fetched and built with the specification's own Makefile.

개요와 논문 정보

한두 문단 소개: 무엇을 검증하는지(MQT-TZ의 RA와 TA를 위협 모델 아래에서 LTL로 model checking), 핵심 결과가 무엇인지(원본에서 위반이 발견되고 patch로 해결된다 등).


## Paper

Geunyeol Yu, Seunghyun Chae, Kyungmin Bae, Sungkun Moon.
[Formal Specification of Trusted Execution Environment APIs](https://doi.org/10.1007/978-3-031-57259-3_5).
FASE 2024, LNCS, Springer.

## Layout

| Path | Contents |
| --- | --- |
| `mqttz/` | The MQT-TZ case study: `Makefile`, `mqttz.toml` (the system and its analyses: `[model-checking]`, the analysis of the paper), `core/` (the model files written by hand), `scripts/` (the experiments of the paper), `models/` (the built models, not tracked). See [mqttz/README.md](mqttz/README.md). |
| `kmgk/` | The KMGK benchmark. Not yet ported to the current specification. |
| `tools/build/` | `tee-build.py` (builds an analysis of a case study), `transform.mk` (the transforms of a spec build: `drop-class-attribute.py`, `ghost.py`, `gen-invisible.py`, DM-Check, maude2lean). |
| `tools/lang/` | `preprocess.py`: preprocesses the C source of a TA into the programs of the model. |
| `tools/dmc/`, `tools/lean/` | `gen-dmc.py` (DM-Check build) and its Maude libraries; `gen-maude2lean.py`. |
| `build/` | Cache (not tracked): the fetched spec revisions and the transformed builds. |

The feature groups of the specification, its test suites and its documentation site are in the
specification repository.

## Contents

```
tee-formal-analysis/
├── README.md                       This guide
├── LICENSE                         License of this artifact (GPL-3.0)
├── config.mk                       Personal settings, gitignored: MAUDE, MAUDE2LEAN paths
├── mqttz/                          The MQT-TZ case study (details in mqttz/README.md)
│   ├── Makefile                    make <analysis>: builds models/<analysis>
│   ├── mqttz.toml                  The system (spec revision, TA preprocessing) and the analyses
│                                   ([model-checking]: dropped attribute, ghost, invisible rules)
│   ├── core/                       The model files written by hand: system, TA (C source and
│   │                               patches), RA, environment, scenarios, threats, properties,
│   │                               entry modules, tests
│   ├── scripts/                    Paper Table 2 and Table 3: run, run-exp, gen-report, gen-table
│   ├── models/                     Built by make, gitignored: one final model per analysis
│   └── output/                     Created by the scripts, gitignored
├── kmgk/                           The KMGK benchmark (not yet ported to the current spec)
├── tools/
│   ├── build/
│   │   ├── tee-build.py            Build an analysis of a case study into C/models/A
│   │   ├── transform.mk            The transforms of a spec build (drop, ghost, invisible, DMC, M2L)
│   │   ├── drop-class-attribute.py Drop a class attribute from rule left-hand sides
│   │   ├── ghost.py                Compose ghost state with the spec rules
│   │   └── gen-invisible.py        Generate the invisible-transition reduction
│   ├── lang/
│   │   └── preprocess.py           Preprocess the C source of a TA into the programs of the model
│   ├── dmc/
│   │   ├── gen-dmc.py              Generate the DM-Check build of the spec
│   │   └── lib/                    Maude libraries of gen-dmc
│   └── lean/
│       └── gen-maude2lean.py       Generate the maude2lean build from the DMC build
└── build/                          Cache, gitignored: fetched spec revisions (build/spec/) and
                                    transformed builds (build/C-A/)
```

## Case studies and analyses

A case study is a directory `C/` with a manifest `C/C.toml` that says what the analyzed system is:
the specification (`[spec]`: repository, revision, features) and the TAs preprocessed from C
(`[ta.KEY]`).  Every other top-level table `[A]` of `C/C.toml` is an analysis `A`, which says how
the system is analyzed: the build of the specification (`mode`: plain, `dmc` for DM-Check or `m2l`
for maude2lean) and its transforms (`[A.drop-class-attribute]`, `[A.ghost]`, `[A.invisible]`).
The model files written by hand are in `C/core/`.  Each case study has its own `C/Makefile`.

`make A` in `C/` (`tools/build/tee-build.py C A`) builds the analysis:

1. the revision of `[spec]` is fetched into `build/spec/<commit>/` (a branch or a tag is fetched
   again at every build; a commit is fetched once);
2. the specification is built with its Makefile and the features of `[spec.features]`, and the
   transforms of `[A]` are applied to it by `tools/build/transform.mk`, in `build/C-A/` (cached;
   the tables of `[A]` are written to `build/C-A/A.toml` for the transforms);
3. `C/models/A/` is written from scratch with the final model, which loads on its own: `src/` (the
   transformed specification), `core/` (a copy of `C/core/`), `ta/` (the preprocessed TAs),
   `model.maude` and `main.maude` (which adds `core/cmd/main.maude`, the entry module of the
   analyses).

The scripts of an analysis run on `C/models/A/`.  `make A SPEC=DIR` uses a checkout of the
specification instead of the revision of `[spec]`.

## Requirements

- Maude 3
- GNU Make, Python 3, git

Set the Maude binary in `config.mk` (gitignored) at the repository root:

```make
MAUDE := /path/to/maude
MAUDE2LEAN := /path/to/maude2lean   # only for make lean
```

## Getting started

```bash
cd mqttz
make model-checking          # mqttz/models/model-checking: the model of the paper experiments
make                         # every analysis of mqttz
make help                    # the analyses
```

The transforms can also be applied to a build of a specification checkout, without a case study,
from the repository root:

```bash
M="make -f tools/build/transform.mk"
$M SPEC=../tee-formal-spec NAME=t CRYPTO=0 test   # the spec without the crypto API, and its tests
$M SPEC=../tee-formal-spec NAME=t DMC=1           # the DM-Check build in build/t
$M NAME=t GHOST=FILE.maude DMC=1                  # compose a ghost module (SPEC is cached)
$M help                                           # settings and targets
```
