#!/bin/sh
# Build the Google KeyMint TA (dev profile, KILL command enabled), the reproduction CA, and the initramfs.
# Upstream clones are read-only inputs (android/, teaclave-v0.4.0/); the build tree is ~/optee-build/aosp.
# Changes to the upstream code are listed in ~/optee-build/keymint/BUILD-NOTES.md.
set -e
W=$HOME/optee-build
A=$(cd "$(dirname "$0")/.." && pwd)
D=$W/build/os/export-ta_arm64
T=$W/aosp/tee/optee/ta/keymint
TOOLCHAIN=nightly-2026-08-05

# TA
cd "$T"
TA_DEV_KIT_DIR=$D cargo +$TOOLCHAIN build --target aarch64-unknown-linux-gnu --release --features dev
O=target/aarch64-unknown-linux-gnu/release
aarch64-linux-gnu-objcopy --strip-unneeded $O/ta $O/stripped_ta
python3 $D/scripts/sign_encrypt.py --uuid dc274baf-5f8c-48cd-89ab-cd9a4d38ed12 --key $D/keys/default_ta.pem \
  --in $O/stripped_ta --out $W/keymint/ta/dc274baf-5f8c-48cd-89ab-cd9a4d38ed12.ta

# CA (reads the generated cases of the analysis, output/diff/cases.h)
CLIENT=$HOME/SV/minoptee/upstream/optee_client/libteec
cd $W/keymint
aarch64-linux-gnu-gcc -O2 -static -Wall -Wno-missing-braces -Wno-unused-function -D_GNU_SOURCE \
  -DDEBUGLEVEL_1 '-DBINARY_PREFIX="KMK"' -I. -I$A/output/diff -I$CLIENT/include -I$CLIENT/src \
  -o kmk-ca app/kmk_ca.c $CLIENT/src/tee_client_api.c $CLIENT/src/teec_trace.c -pthread
echo "built TA and CA"
