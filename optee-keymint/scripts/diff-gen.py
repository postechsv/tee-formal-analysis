#!/usr/bin/env python3
"""Transition-coverage test cases for the instance model (keymint-instance.maude, mirrored in
scripts/diff_model.py).

For each scenario: breadth-first search over the model states from the scenario's initial sessions, keeping
one shortest representative sequence per state.  For every reached state s and every candidate operation o
from s (including the ones the model rejects), the case is  rep(s) + [o]  with the model's prediction of each
operation.  If the abstraction is right, the TA gives the same answer for the same state; this is run on the
real TA by kmk-ca batch and compared by scripts/diff-check.py.

Also reports, per scenario, whether the attacker goal is reachable in the model (cross-check with Maude:
S1, S3, S4, S5, S6 reachable; S2 not reachable).

    diff-gen.py  ->  output/diff/SCENARIO.cases  (lines:  ops|pred)  and  output/diff/summary.txt
"""
import os
import sys
from collections import deque

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from diff_model import apply, candidates  # noqa: E402

# scenario: (module, initial sessions); the goal: attacker value set after a destruction
SCENARIOS = {
    'base':  ('KM-INST', []),              # S1, S5
    'hold':  ('KM-INST', ['open:hal']),    # S2
    'hal':   ('KM-HAL', ['open:hal']),     # S3
    'att':   ('KM-INST', ['open:att']),    # S4
    'panic': ('KM-PANIC', ['open:hal']),   # S6
}


def start(module, prefix):
    st = (None, frozenset(), (False, False, False))
    for op in prefix:
        st = apply(st, op, module)
        assert st is not None, op
    return st


def ok_att(state):
    """Model goal: the attacker's value is in an instance that was destroyed after boot info was set."""
    inst, held, (L, D, P) = state
    return inst is not None and inst[1] == 'att' and D


def main():
    os.makedirs('output/diff', exist_ok=True)
    summary = []
    for name, (module, prefix) in SCENARIOS.items():
        s0 = start(module, prefix)
        rep = {s0: prefix}           # state -> representative sequence (ops)
        queue = deque([s0])
        cases = []
        reached_goal = False
        while queue:
            s = queue.popleft()
            reached_goal = reached_goal or ok_att(s)
            for o in candidates(s, module):
                if o == 'setlegit:boot' and s[2][2]:
                    continue          # boot provisions once: environment assumption
                seq = rep[s] + [o]
                # predict every operation of the case by replaying the model on the case
                st = start(module, [])
                preds = []
                for op in seq:
                    nxt = apply(st, op, module)
                    preds.append(nxt is not None)
                    st = nxt if nxt is not None else st
                cases.append((seq, preds))
                nxt = apply(s, o, module)
                if nxt is not None and nxt not in rep:
                    rep[nxt] = seq
                    queue.append(nxt)
        with open('output/diff/%s.cases' % name, 'w') as f:
            for seq, preds in cases:
                f.write('%s|%s\n' % (','.join(seq), ''.join('1' if p else '0' for p in preds)))
        line = '%-6s module=%-9s states=%-4d cases=%-6d goal_reachable=%s' % (
            name, module, len(rep), len(cases), reached_goal)
        print(line)
        summary.append(line)
    with open('output/diff/summary.txt', 'w') as f:
        f.write('\n'.join(summary) + '\n')


if __name__ == '__main__':
    main()
