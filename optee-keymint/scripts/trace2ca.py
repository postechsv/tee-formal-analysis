#!/usr/bin/env python3
"""Turn an exported counterexample trace (output/paths/NAME.trace, rules in order) into the operation
list that the reproduction CA runs on the real TA (~/optee-build/keymint/app/kmk_ca.c, mode `trace`).

    trace2ca.py NAME > output/ca-ops/NAME.ops

Rule -> operation (no other step is added; the initial sessions of the scenario come first):
    open-new-X, open-join-X     -> open:X
    close-keep-X, close-last-X  -> close:X
    set-boot                    -> setlegit:boot
    set-att                     -> setatt:att
    end-boot / end-att          -> earlyend:boot / earlyend:att
    panic                       -> kill:C  (C: the client that sends KILL, one of the open sessions)
A panic destroys every session of the model (GP: the instance is gone), so the open set is emptied.
"""
import re
import sys

# initial sessions of each scenario (the state the search started from)
INITIAL = {
    's1': [], 's3': ['hal'], 's4': ['att'], 's5': [], 's6': ['hal'],
}
RULE = re.compile(r'^===\[ c?rl \[([^\]]+)\]', re.M)


def main():
    name = sys.argv[1]
    text = open('output/paths/%s.trace' % name, encoding='utf-8').read()
    rules = RULE.findall(text)
    open_set = list(INITIAL[name])
    ops = ['open:%s' % c for c in open_set]
    for r in rules:
        if r.startswith('open-new-') or r.startswith('open-join-'):
            c = r.split('-')[-1]
            ops.append('open:%s' % c)
            open_set.append(c)
        elif r.startswith('close-keep-') or r.startswith('close-last-'):
            c = r.split('-')[-1]
            ops.append('close:%s' % c)
            open_set.remove(c)
        elif r == 'set-boot':
            ops.append('setlegit:boot')
        elif r == 'set-att':
            ops.append('setatt:att')
        elif r in ('end-boot', 'end-att'):
            c = r.split('-')[1]
            ops.append('earlyend:%s' % c)
        elif r == 'panic':
            killer = 'hal' if 'hal' in open_set else open_set[0]
            ops.append('kill:%s' % killer)
            open_set = []
        else:
            sys.exit('no operation for rule %s' % r)
    print(','.join(ops))


if __name__ == '__main__':
    main()
