# KMGK

The Keymaster and Gatekeeper trusted applications of [linaro-swg/kmgk](https://github.com/linaro-swg/kmgk)
(Android keystore and lock-screen authentication on OP-TEE), with their clients, modeled on top of
the TEE formal specification.

## Layout

```
kmgk/
├── Makefile                    make <analysis>: builds models/<analysis>
├── model-checking.toml         The analysis of the session checks: the system (spec revision, TA
│                               preprocessing) and the invisible rules
├── dmc.toml                    The DM-Check build of the system, with the DM-Check directives of the spec
├── core/                       The model files written by hand
│   ├── main.maude              Loads kmgk-data and kmgk-instance-data
│   ├── kmgk-data.maude         Constants of the upstream headers (KMGK-DATA) and the names of
│   │                           the entry points (KMGK-PROGRAM-DECL)
│   ├── kmgk-instance-data.maude  The instance data of the TAs (loadGlobals, storeGlobals): the
│   │                           globals that an instance keeps from one command to the next
│   ├── ta/gatekeeper/          Gatekeeper TA: upstream ta_gatekeeper.h, failure_record.[ch],
│   │                           gatekeeper_ta.c as published, model.patch, template.maude
│   ├── ta/keymaster/           Keymaster TA: upstream operations.[ch], auth.c, keystore_ta.c as
│   │                           published, model.patch, template.maude
│   ├── ra/hal.maude            The Gatekeeper HAL (C++ upstream), in the model's syntax
│   ├── ra/keystore.maude       A keystore client of the Keymaster TA, in the model's syntax
│   ├── scenarios/base.maude    Initial states: the clients, the TrustedOS, the two TA instances
│   │                           and their storages (master key, auth token key)
│   ├── scenarios/sessions.maude, scenarios/panic.maude   The session scenarios (below)
│   ├── cmd/sessions.maude      The searches of the session scenarios
│   └── cmd/main.maude          Entry module of the analyses (ANALYSIS-CMD)
└── models/, output/            Built by make and export-paths, gitignored
```

## Building

`model-checking.toml` and `dmc.toml` name the revision of the spec (`[spec]`); `make` fetches it:

    make model-checking
    make A SPEC=DIR             # the analysis A on a spec checkout instead

## What the model keeps

Both TAs are preprocessed from the upstream C sources by `tools/lang-preprocess.py`; their
`model.patch` lists every change.  In short:

* Gatekeeper: Enroll and Verify with the failure records (failure_record.c) and the throttling of
  failed attempts, the master key and the HMAC signatures of password handles.  The failure record
  table is a global of the TA: its dispatcher keeps it from one command to the next with
  loadGlobals and storeGlobals (core/kmgk-instance-data.maude, the instance data of the TA).  The auth token that Verify mints (TA_MintAuthToken, a call of the Keymaster TA) is
  not in the model yet.
* Keymaster: the operation table (operations.c) and begin, update, finish and abort for HMAC keys,
  with the authorization checks of upstream (TA_check_params, TA_do_auth, TA_check_auth_token).
  Key blobs are not encrypted, and the other algorithms, parameters and commands are left out.

The model has no clock (the system time is always 0), so a throttling timeout never expires.

## Session checks

`core/scenarios/sessions.maude` and `core/cmd/sessions.maude`: the state that an instance keeps
across its sessions.  Both TAs are single-instance, multi-session and not kept alive, so the
last TEEC_CloseSession destroys the instance with its memory.

    make model-checking
    cd models/model-checking && maude -no-banner core/cmd/sessions.maude

* Gatekeeper: after five wrong guesses, a client that closes its session and opens a new one is
  no longer throttled (its failure records were in the destroyed instance), unless another
  session kept the instance alive.
* Keymaster: an operation begun in a session survives the close of that session while another
  session keeps the instance, and a new session finishes it (TA_CloseSessionEntryPoint does not
  abort the operations of the session); without another session it is gone.
* Gatekeeper with a panic (core/scenarios/panic.maude): a failure of the TEE (teeFault) panics the
  instance while another client keeps a session open on it.  A panicked instance is destroyed at
  once ([Internal Core] 2.3.3), so the throttled attacker gets ERROR_INVALID in a new session: the
  other session does not keep the failure records.

## Paths for the counterexample viewer

    export-paths [NAME ...]     (MAUDE=path/to/maude if maude is not on PATH)

export-paths (kmgk-paths/export-paths of tee-formal-analysis-misc) writes output/paths/NAME.log for
every path (or the given ones), which
tools/ce-viewer/ce-viewer.html opens: the path of a `search [1]` for the outcome of the scenario,
turned into the `counterexample(...)` form by tools/ce-viewer/path2ce.py.  The Gatekeeper paths are
17 to 19 MB each.

* gk-alone-reset, gk-holder-throttled, gk-holder-late-reset, gk-holder-panic-reset
* km-alone-gone, km-holder-survives, km-holder-late-gone
