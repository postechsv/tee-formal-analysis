#!/usr/bin/env python3
"""Shortest paths of the KM-INST / KM-HAL / KM-PANIC models, written in the format of a Maude
`show path` log (state N, Sys: ... / ===[ rl [LABEL] : ... ]===> ), so that tools/ce-viewer/path2ce.py
can read them.  The rules are the ones of keymint-instance.maude; the paths are found by BFS here,
and every step is then checked by Maude (search [1] ... =>1 ...), see --check.

    path-trace.py MODULE  (kminst | khal | kpanic)  SCENARIO  > LOG
"""
import sys
from collections import deque

# state: (inst, ss, hist); inst = None (noInst) or (E, BI); ss = (boot, hal, att); hist = (L, D, P)
NOINST = None


def term(s):
    inst, ss, hist = s
    if inst is None:
        it = 'noInst'
    else:
        e, bi = inst
        bim = {'unset': 'unset', 'legit': 'legitV', 'att': 'attV'}[bi]
        it = 'inst(%s, %s)' % ('true' if e else 'false', bim)
    b, h, a = ss
    st = 'ss(%s, %s, %s)' % tuple('true' if x else 'false' for x in (b, h, a))
    L, D, P = hist
    ht = 'hist(%s, %s, %s)' % tuple('true' if x else 'false' for x in (L, D, P))
    return 'sys(%s, %s, %s)' % (it, st, ht)


def successors(s, module):
    inst, ss, hist = s
    b, h, a = ss
    L, D, P = hist
    out = []
    empty = (False, False, False)
    if inst is None:
        if ss == empty:
            for name, flag in (('open-new-boot', 0), ('open-new-hal', 1), ('open-new-att', 2)):
                n = [False, False, False]; n[flag] = True
                out.append((name, ((True, 'unset'), tuple(n), hist)))
        return out
    E, BI = inst
    # open-join
    if not b:
        out.append(('open-join-boot', (inst, (True, h, a), hist)))
    if not h:
        out.append(('open-join-hal', (inst, (b, True, a), hist)))
    if not a:
        out.append(('open-join-att', (inst, (b, h, True), hist)))
    # set-boot / set-att / end-boot / end-att
    if E and BI == 'unset' and b and not L and not P:
        out.append(('set-boot', ((True, 'legit'), ss, (True, D, True))))
    if E and BI == 'unset' and a:
        out.append(('set-att', ((True, 'att'), ss, hist)))
    if E and b:
        out.append(('end-boot', ((False, BI), ss, hist)))
    if E and a:
        out.append(('end-att', ((False, BI), ss, hist)))
    # close-keep (a session leaves while another is open)
    if b and (h or a):
        out.append(('close-keep-boot', (inst, (False, h, a), hist)))
    if a and (b or h):
        out.append(('close-keep-att', (inst, (b, h, False), hist)))
    if module in ('khal', 'kpanic') and h and (b or a):
        out.append(('close-keep-hal', (inst, (b, False, a), hist)))
    # the last session closes: the instance is destroyed
    last = {'close-last-boot': (True, False, False), 'close-last-att': (False, False, True)}
    if module in ('khal', 'kpanic'):
        last['close-last-hal'] = (False, True, False)
    for name, pat in last.items():
        if ss == pat:
            out.append((name, (None, (False, False, False), (False, D or L, P))))
    if module == 'kpanic':
        out.append(('panic', (None, (False, False, False), (False, D or L, P))))
    return out


def bfs(start, module, goal):
    prev = {start: None}
    q = deque([start])
    while q:
        s = q.popleft()
        if goal(s):
            path = []
            while s is not None:
                path.append(s)
                p = prev[s]
                s = p[0] if p else None
            return [st for st in reversed(path)], prev
        for name, t in successors(s, module):
            if t not in prev:
                prev[t] = (s, name)
                q.append(t)
    return None, prev


SCEN = {
    # S1: boot alone, att sets after the last session closed
    's1': ('kminst', (None, (False, False, False), (False, False, False)),
           lambda s: s[0] == (True, 'att') and s[2][1] and s[1][2] is not None and s[2][1]),
    # S3: HAL may close as the last session (KM-HAL)
    's3': ('khal', ((True, 'unset'), (False, True, False), (False, False, False)),
           lambda s: s[0] == (True, 'att') and s[2][1]),
    # S4: att holds, boot closes, att closes last, reopens, sets
    's4': ('kminst', ((True, 'unset'), (False, False, True), (False, False, False)),
           lambda s: s[0] == (True, 'att') and s[2][1]),
    # S5: att opens and sets before boot provisions (the legitimate value is then refused)
    's5': ('kminst', (None, (False, False, False), (False, False, False)),
           lambda s: s[0] == (True, 'att') and not s[2][2]),
    # S6: HAL holds, panic destroys the instance, HAL reconnects, att sets
    's6': ('kpanic', ((True, 'unset'), (False, True, False), (False, False, False)),
           lambda s: s[0] == (True, 'att') and s[2][1]),
}


def main():
    module, scen = sys.argv[1], sys.argv[2]
    mod, start, goal = SCEN[scen]
    if mod != module:
        sys.exit('scenario %s runs in module %s' % (scen, mod))
    path, prev = bfs(start, mod, goal)
    if path is None:
        sys.exit('no solution: %s' % scen)
    # the rule names along the path
    rules = []
    for s in path[1:]:
        rules.append(prev[s][1])
    print('search %s: %s (BFS, %d states explored)' % (scen, mod, len(prev)))
    for i, s in enumerate(path):
        print('state %d, Sys: %s' % (i, term(s)))
        if i < len(rules):
            print('===[ rl [%s] : step ]===>' % rules[i])


if __name__ == '__main__':
    main()
