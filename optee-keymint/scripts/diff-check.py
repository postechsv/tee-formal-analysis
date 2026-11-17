#!/usr/bin/env python3
"""Compare the real TA (kmk-ca batch log) with the model prediction for every case of output/diff.

    diff-check.py LOG > output/diff/result.txt

Per operation the TA accepts when: open/close -> TEEC rc 0; setlegit/setatt/earlyend -> TEEC rc 0 and the
KeyMint error code is 0; kill -> TEEC TARGET_DEAD (the TA panicked, as the dev KILL does).
The model's prediction for the same case must agree on every operation.
Goal: the attacker's SetBootInfo is accepted after an accepted boot SetBootInfo in the same case.  A case
with the attacker accepted implies a fresh instance (a live instance keeps the boot info, and the attacker is
then refused), so the TA-side goal is this observable proxy.
"""
import glob
import os
import re
import sys

LINE = re.compile(r'^R (\d+) (\S+) (\d+) (\S+) (\S+) (0x[0-9a-f]+) (\S+)$')
TARGET_DEAD = 0xffff3024
NAMES = {0: 'OK', -1: 'RootOfTrustAlreadySet', -73: 'EarlyBootEnded'}


def error_code(hexrsp):
    """KeyMint error code of a PerformOpResponse: the leading 00, then an array whose first item is the code."""
    if not hexrsp.startswith('0082'):
        return None
    b = bytes.fromhex(hexrsp)
    i = 2
    if b[i] <= 0x17:
        return b[i]
    if 0x20 <= b[i] <= 0x37:
        return -1 - (b[i] - 0x20)
    if b[i] == 0x38:
        return -1 - b[i + 1]
    return None


def cases():
    rows = []
    for path in sorted(glob.glob('output/diff/*.cases')):
        scen = os.path.basename(path).split('.')[0]
        for line in open(path):
            ops, preds = line.strip().split('|')
            rows.append((scen, ops.split(','), [p == '1' for p in preds]))
    return rows


def main():
    log = sys.argv[1]
    rows = cases()
    ta = {}
    for line in open(log, errors='replace'):
        m = LINE.match(line.strip())
        if not m:
            continue
        k, scen, idx, client, op, rc, rsp = m.groups()
        ta.setdefault(int(k), []).append((scen, op, int(rc, 16), rsp))
    total_ops = mismatches = 0
    per = {}
    bad = []
    goal_ta = {}
    goal_model = {}
    for k, (scen, ops, preds) in enumerate(rows):
        got = ta.get(k, [])
        if len(got) != len(ops):
            bad.append('case %d (%s): %d of %d operations logged' % (k, scen, len(got), len(ops)))
            continue
        acc = []
        for (s, op, rc, rsp) in got:
            if op in ('open', 'close'):
                a = rc == 0
            elif op == 'kill':
                a = rc == TARGET_DEAD
            else:
                code = error_code(rsp) if rc == 0 else None
                a = rc == 0 and code == 0
                if rc == 0 and code is None:
                    bad.append('case %d: unparsed response %s' % (k, rsp))
            acc.append(a)
        stats = per.setdefault(scen, [0, 0, 0])  # cases, ops, mismatching ops
        stats[0] += 1
        for i, (a, p) in enumerate(zip(acc, preds)):
            stats[1] += 1
            total_ops += 1
            if a != p:
                stats[2] += 1
                mismatches += 1
                bad.append('case %d (%s) op %d %s: model %s, TA %s' % (
                    k, scen, i, ops[i], 'accepts' if p else 'rejects', 'accepts' if a else 'rejects'))
        # goal proxy on the TA side and the model side
        legit = False
        g_ta = g_m = False
        for i, op in enumerate(ops):
            if op == 'setlegit:boot' and acc[i]:
                legit = True
            if op == 'setatt:att':
                if acc[i] and legit:
                    g_ta = True
                if preds[i] and legit:
                    g_m = True
        goal_ta[scen] = goal_ta.get(scen, False) or g_ta
        goal_model[scen] = goal_model.get(scen, False) or g_m
    print('cases: %d  operations: %d  mismatching operations: %d' % (len(rows), total_ops, mismatches))
    print('scenario  cases  operations  mismatches  goal(model)  goal(TA)')
    for scen in sorted(per):
        c, o, mm = per[scen]
        print('%-9s %-6d %-11d %-11d %-12s %s' % (scen, c, o, mm, goal_model.get(scen), goal_ta.get(scen)))
    for b in bad[:60]:
        print('MISMATCH', b)
    if len(bad) > 60:
        print('... %d more' % (len(bad) - 60))


if __name__ == '__main__':
    main()
