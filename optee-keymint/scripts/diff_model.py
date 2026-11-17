#!/usr/bin/env python3
"""Operation-level model of keymint-instance.maude, used to predict the real TA for every operation
sequence (scripts/diff-gen.py enumerates; scripts/diff-check.py compares with the QEMU run).

State: (inst, held, hist) with inst = None (no instance) or (E, BI), BI in {'unset','legit','att'},
held = frozenset of clients with a session, hist = (L, D, P) as in the Maude model.

apply(state, op, module) -> new state, or None when the model has no transition for the operation.
Operations: open:C close:C setlegit:boot setatt:att earlyend:C kill:C.
Conventions (stated, not checked by the TA):
  * boot provisions boot info once (P): a second setlegit is an environment assumption, never enumerated.
  * the hal closes only in modules KM-HAL and KM-PANIC (as in the Maude model).
  * earlyend is accepted whenever the client holds a session (the TA checks nothing, lib.rs:991).
  * setatt with the same value again is accepted without change (kmr-ta lib.rs:564-571); the Maude model
    has no transition for it, which changes no state.
"""

CLIENTS = ('hal', 'boot', 'att')


def apply(state, op, module):
    inst, held, hist = state
    L, D, P = hist
    kind, _, c = op.partition(':')
    if kind == 'open':
        if c in held:
            return None
        if inst is None:
            if held:
                return None
            return ((True, 'unset'), frozenset([c]), hist)
        return (inst, held | {c}, hist)
    if kind == 'close':
        if c not in held or (c == 'hal' and module == 'KM-INST'):
            return None
        rest = held - {c}
        if rest:
            return (inst, rest, hist)
        return (None, frozenset(), (False, D or L, P))
    if kind == 'setlegit':
        if c != 'boot' or 'boot' not in held or inst is None or inst != (True, 'unset') or L or P:
            return None
        return (((True, 'legit')), held, (True, D, True))
    if kind == 'setatt':
        if c != 'att' or 'att' not in held or inst is None or not inst[0]:
            return None
        if inst[1] == 'unset':
            return (((True, 'att')), held, hist)
        if inst[1] == 'att':
            return state      # same value again: accepted, no change (kmr-ta lib.rs:564-571)
        return None           # a different value is refused (RootOfTrustAlreadySet)
    if kind == 'earlyend':
        if c not in held or inst is None:
            return None
        return ((False, inst[1]), held, hist)
    if kind == 'kill':
        if module != 'KM-PANIC' or c not in held:
            return None
        return (None, frozenset(), (False, D or L, P))
    raise ValueError(op)


def candidates(state, module):
    """Operations to try from a state: every client action on a client that holds (or may open) a session."""
    inst, held, hist = state
    ops = []
    for c in CLIENTS:
        if c not in held:
            ops.append('open:' + c)
        else:
            if c != 'hal' or module != 'KM-INST':
                ops.append('close:' + c)
            ops.append('earlyend:' + c)
            if module == 'KM-PANIC':
                ops.append('kill:' + c)
    ops.append('setlegit:boot')
    ops.append('setatt:att')
    return ops
