#!/bin/sh
# The whole pipeline, in order.  Run from the analysis directory:  sh scripts/repro.sh
#   1. Maude: the six scenarios (S1-S6) with their expected answers.
#   2. Maude-checked counterexample paths (ce-viewer format).
#   3. Transition-coverage cases from the model (python) and the operation lists of the paths.
#   4. Build the TA and the CA (scripts/build-target.sh).
#   5. QEMU: the cases on the real TA (kmk-ca batch), log in ~/optee-build/run/batch-LOG.
#   6. Compare TA and model per operation (scripts/diff-check.py), write output/diff/result.txt.
set -e
MAUDE=${MAUDE:-$HOME/sv-comp-maude/Maude-3.5.1-linux-x86_64/maude}
W=$HOME/optee-build
mkdir -p output/paths output/diff output/ca-ops $W/keymint/out
echo "== 1. scenarios"
"$MAUDE" -no-banner keymint-scenarios.maude > $W/keymint/out/scenarios.log 2>&1 || true
grep -E "^Solution|^No solution" $W/keymint/out/scenarios.log
echo "== 2. paths"
sh scripts/export-paths
echo "== 3. cases"
python3 scripts/diff-gen.py
python3 scripts/diff-emit.py
for s in s1 s3 s4 s5 s6; do python3 scripts/trace2ca.py $s > output/ca-ops/$s.ops; done
echo "== 4. build"
sh scripts/build-target.sh
echo "== 5. run on the TA: build the initramfs (TESTS='/bin/kmk-ca batch') and run QEMU:"
echo "   cd $W && TESTS='/bin/kmk-ca batch' EXTRA_CA=$W/keymint/kmk-ca EXTRA_TA=$W/keymint/ta/dc274baf-5f8c-48cd-89ab-cd9a4d38ed12.ta python3 app/build.py"
echo "   $W/keymint/run-qemu.sh $W/run/batch-LOG 1500"
echo "== 6. compare (after the run):  python3 scripts/diff-check.py $W/run/batch-LOG > output/diff/result.txt"
