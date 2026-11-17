# MQT-TZ

The MQT-TZ broker: its rich application (RA) and trusted application (TA), with the publishers,
subscribers and broker around them, modeled on top of the TEE formal specification.

## Layout

```
mqttz/
├── Makefile                    make <analysis>: builds models/<analysis>
├── model-checking.toml         The analysis: the system (spec revision, TA preprocessing),
│                               the dropped attribute, ghost and invisible rules
├── core/                       The model files written by hand
│   ├── main.maude              Loads the model files
│   ├── system.maude            MQT-TZ module: all entity behaviors, the RA and the TA
│   ├── ta/                     The trusted application
│   │   ├── hot_cache_ta.c      Upstream C source, as published
│   │   ├── model.patch         Modeling changes to the C code
│   │   ├── fix.patch           Code-level fix (mqttzTaPatched)
│   │   └── template.maude      Template of broker-ta.maude
│   ├── ra/
│   │   └── broker-ra.maude     RA programs mqttzHost and mqttzHostPatched
│   ├── env/                    The other participants
│   │   ├── base.maude          Keys, topics, subscriptions
│   │   ├── entity.maude        Abstract entity and client
│   │   ├── client.maude        Publishers and subscribers
│   │   ├── broker.maude        Broker: storing and re-encrypting messages
│   │   └── ta-data.maude       TA constants (TA_* macros of hot_cache_ta.h)
│   ├── scenarios/              Initial states
│   │   ├── aux.maude           Initialization functions (clients, keys)
│   │   ├── base.maude          The paper scenario: 2 publishers, 2 subscribers, 1 broker,
│   │   │                       2 topics
│   │   └── inv.maude           Smaller scenarios scenario-inv1..4
│   ├── threats/
│   │   ├── main.maude          Loads the threats
│   │   ├── oom.maude           Out-of-memory threat (OOM-THREAT)
│   │   └── msg.maude           Message intruder (MSG-THREAT, initInt)
│   ├── properties/
│   │   ├── propositions.maude  State propositions (read the ghost state)
│   │   └── properties.maude    LTL properties p1–p6
│   ├── cmd/                    Entry modules of the analyses (ANALYSIS-CMD)
│   │   ├── main.maude          system + scenarios/base + threats + properties
│   │   └── inv.maude           system + scenarios/inv + threats + properties
│   └── tests/
│       ├── main.maude          Test driver
│       └── cases/              Calls of the TA, per API group: transient, persistent,
│                               data-stream, generic, cryptographic
├── scripts/                    Paper Table 2 and Table 3, on models/model-checking
│   ├── run                     run PROP THREAT [-patch] [MAUDE_DIR] [LOG_DIR] [-silent]
│   ├── run-exp                 run-exp table2|table3|smoke [-non-parallel] [-j N]
│   ├── gen-report              Logs of a table → table<i>-report.csv
│   └── gen-table               Report → table<i>.html
├── models/                     Built by make <analysis>, gitignored
│   └── model-checking/         src/ (the spec), core/, ta/, model.maude, main.maude
└── output/                     Created by the scripts, gitignored
```

## The system

`model-checking.toml` names the revision of the specification (`[spec]`, with the feature groups that the spec selects) and
the TA.  The TA programs are preprocessed from `core/ta/hot_cache_ta.c`, the C source as
published, by `tools/lang-preprocess.py` into `models/<analysis>/ta/broker-ta.maude`: `mqttzTA`
from the source with `core/ta/model.patch` (the modeling changes of the C code), and
`mqttzTaPatched` with `core/ta/fix.patch` on top (the code-level fix).  What the model leaves out
or changes in the C code (logging, timing, buffer sizes, the split of the TEE_Param memory
references, ...) is in `core/ta/model.patch`; the `[ta.broker]` table of the manifest only says
what to preprocess.  The entry point of the model, `void main`, is `TA_InvokeCommandEntryPoint`,
preprocessed like the other functions.

## Model checking

`model-checking.toml` is the analysis of the paper: the LTL properties p1–p6 of
`core/properties/` under no threat, the out-of-memory threat and the message intruder.  It builds
the specification with

- `[drop-class-attribute]`: `status : normal` dropped from the left-hand side of the TA-side rules,
  so that the TA goes on after a memory error of the out-of-memory threat, as in the paper
  artifact;
- `[ghost]`: the ghost attribute `running` of the TA, which the LTL propositions read;
- `[invisible]`: the invisible-transition reduction of Section 8.1 of the paper.

```bash
make model-checking                     # models/model-checking
scripts/run-exp table2                  # output/table2/{maude-files,logs}, in parallel
scripts/run-exp table3 -non-parallel
cd output
../scripts/gen-report table2            # table2-report.csv
../scripts/gen-table table2-report.csv  # table2.html
```

Table 2 checks the original RA and TA, Table 3 the patched ones.  `scripts/run-exp smoke` runs
three quick checks (p3 non, p3 oom, p2 msg; under a minute) into `output/smoke/`, to see the
scripts and their output without the full tables.

Each table gives `output/TABLE/maude-files/` (the Maude input of each check),
`output/TABLE/logs/` (the Maude output), and, after gen-report and gen-table,
`output/TABLE-report.csv` (property, threat, holds or not, thousands of states, seconds) and
`output/TABLE.html` (the table of the paper).
`scripts/run PROP THREAT [-patch] [MAUDE_DIR] [LOG_DIR] [-silent]` writes and runs one of
the checks (PROP `p1`..`p6`, THREAT `non`, `oom` or `msg`, `-patch` for the patched programs).
