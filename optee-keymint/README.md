# optee-keymint: instance lifetime of the Google OP-TEE KeyMint TA

Target: `android.googlesource.com/tee/optee/ta/keymint` (ffced1f, Rust) on `platform/system/keymint`
(kmr-ta, fda4e68), built for OP-TEE (Teaclave v0.4.0 layout, small patches: ~/optee-build/keymint/BUILD-NOTES.md).

Question: can an REE client make the TA's once-per-boot boot info (and early-boot state) be set by an attacker?

## Pipeline (`sh scripts/repro.sh` prints the steps)
1. `keymint-instance.maude` + `keymint-scenarios.maude`: Maude search for S1-S6 (instance model).
2. `scripts/export-paths`: counterexample paths (BFS in `scripts/path-trace.py`, each step checked by Maude `=>1`),
   written in ce-viewer format to `output/paths/`.
3. `scripts/trace2ca.py`: each path -> operation list (`output/ca-ops/`); the real TA runs them (CA mode `trace`).
4. `scripts/diff-gen.py` + `scripts/diff_model.py`: transition-coverage cases: BFS over the operation-level model
   states; per state a representative sequence plus every candidate operation (accepted and rejected).
   `output/diff/*.cases`, `cases.h` (`scripts/diff-emit.py`).
5. `scripts/build-target.sh`: TA (dev profile: KILL command), CA (`~/optee-build/keymint/app/kmk_ca.c`).
6. Real TA: `kmk-ca batch FROM-TO`, one QEMU boot per chunk of 150 cases (`~/optee-build/keymint/run-batch.sh`).
   A boot with many TA panics runs out of secure-world resources; the last 14 cases were rerun in a fresh boot.
7. `scripts/diff-check.py LOG > output/diff/result.txt`: per operation, the TA answer against the model.

## Results
- Maude (S1-S6): S1, S3, S4, S5, S6 attacker value reachable; S2 (HAL keeps its session) not reachable.
- Model vs TA, all 1,924 cases, 11,814 operations: 0 mismatching operations.
  Attacker-goal existence agrees for every scenario (base, hold, hal, att, panic).
- Path runs (`output/paths`, operations in `output/ca-ops`) are among the cases: each path is a
  representative sequence of its goal state.

## Assumptions and limits (stated in the code)
- The boot component provisions boot info once (environment assumption, not enumerated).
- The HAL closes its session only in KM-HAL/KM-PANIC; in KM-INST it never closes (S2).
- TA panic is the dev-only KILL command; no REE request was found to panic the TA (see handoff, section 12).
- Real HAL session policy for this TA is not public (see handoff, section 12).
- Coverage is over the abstract states of the model, not over all sequences.

## Model corrections made from the TA (both recorded in the model files)
- end-boot/end-att: the TA checks nothing (lib.rs:991); the Maude precondition on boot info was removed.
- setatt with the same value again is accepted without change (kmr-ta lib.rs:564-571).
