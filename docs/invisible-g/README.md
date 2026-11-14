# G taken from the artifact: what is the same, what differs (2026-11-13)

The G of a case study is the [invisible] rules of its manifest (case-studies/mqttz/mqttz.toml, which
records the rules kept visible and the notes per rule; until 2026-11-14 they were in a table
decisions.tsv here).  `make mqttz INVISIBLE=1` generates invisible-reduction.maude from it with
tools/gen-invisible.py; spec/src/invisible-reduction.maude is the spec's own copy of the same G.
Each equation is an exact copy of its rule (118 when this note was written, 136 at spec cf579b8).  side-by-side.txt lists, per API function, the artifact rules
(A, G = in artifact G) next to the current rules (C, G = in the old G).

## 1. G: old, new, artifact

| kind (current spec) | old G | new G |
|---|---|---|
| K rules | lookup, lookup-lv, assign, if-true, if-false | all except lookup and assign (11) |
| G3 | 3 (2 equations without `state-changed : false`) | 3, exact copies |
| TA start rules | 63 | 29 |
| TA mid-stage rules | 0 | 11 |
| TA finish rules | 47 | 28 |
| rules on several objects (object side) | 0 | 33 |
| TA panic rules | 0 | 3 (+1 on several objects) |
| API functions with G rules | all except enumerator and tee-client | the 19 with artifact G rules |

## 2. Where the new G still differs from the artifact G

1. Equations are copies of the current rules.  The 11 artifact equations that differ from their
   rule or have no rule (e.g. free-transient-not-null-subroutine finishing the call at once)
   are not reproduced.
2. Behavior the artifact does not have stays visible: set-operation-key-clear,
   set-operation-key-uninitialized-key-panic, open-persistent-default-private-storage,
   open-persistent-storage-id-not-found, close-and-delete-persistent-corrupt-subroutine,
   read/write/delete-access-panic, copy-object-attrs-copy-attrs-fail, copy-object-attrs-*-panic,
   write-object-data-top-level-overflow, cipher-init-panic, populate-transient-*-panic,
   reset-oper-fail, reset-oper-try-reset-fail, setOperationKey2.
3. Judgment calls: create-persist-transform and create-persist-transform-new stay visible (the
   artifact transient-object step create-persistent-subroutine-2 is not in its G); bindV and
   bindS are in G, so a value parameter costs one visible write (the assign), like
   $callByRefInst(V) in the artifact.
4. Taken over from the artifact although it breaks the paper criteria: panic rules in G
   (set-operation-key-panic, cipher-update-panic, close-and-delete-persistent-panic,
   create-persistent-abnormal-storage-panic: panic.TA is not invisible); object-side rules on
   two objects; while and fCall as equations (termination relies on the program).
5. Coherence: read-, write- and delete-access-panic (init stage, not in G) are enabled in the
   same state as a G start rule, so under G they never fire.  The artifact has no such rules.

## 3. Remaining state difference (NON, unpatched, G on): 28,870 vs 36,024

Same decomposition as ../../state-count: 11 TA calls in both models; publisher interleaving
6.64 states per TEE state in both while the TA runs.

| phase | current | artifact |
|---|---|---|
| TA running: states | 26,134 | 29,930 |
| TA running: steps per call | 358 | 410 |
| TA idle (RA): states | 2,736 | 6,094 |
| RA steps per request | 33 | 79 |

Steps of one TA call (../../state-count/cur-newG-path.txt, art-path.txt; classification of the
current assignments by the continuation after them, a heuristic):

| step | current | artifact |
|---|---|---|
| memory read | 164 (18 inside API stubs) | 182 (leval) |
| memory write: statements and output write-back | 99 | 97 (loc :=) |
| memory write: parameter binding of program functions | 26 | 2 ($callByRefInst V) |
| memory write: parameter binding of API stubs | 60 | 0 (API arguments are equations) |
| declarations | 0 (hoisted by equations) | 104 (var 34, $structMemDecl 59, $structNameDecl 11) + $clearMem 4 |
| storage service | 8 (1 rule per request) | 20 (service-receive, get-storage-status/check-file-exist, service-finish) |
| end of call | 1 | 1 |
| total | 358 | 410 |

RA steps per request: current 26 + 7 (reads 8, writes 17, SMC steps 8); artifact 54 + 25
(reads 28, writes 25, declarations 15, SMC steps 10).

None of these come from G: they come from the K semantics (declarations as rules in the artifact,
hoisted in the current spec), the API stubs (current spec binds API arguments as function
parameters), the TA and RA program texts (by-value parameters, write-back of the outputs), and
the storage model (TeeOSKernel service with three steps vs Storage object with one).

The matrix run with the new G was stopped after 7 cells (../../g-artifact/logs/status.tsv).
