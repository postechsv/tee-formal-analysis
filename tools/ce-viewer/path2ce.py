#!/usr/bin/env python3
"""Turn the output of a Maude `show path N .` into a log that ce-viewer.html loads.

    path2ce.py PATH-LOG [--title TEXT] > OUT.log

The states of the path become the steps of `result ModelCheckResult: counterexample(...)`: each
state is paired with the label of the rule that leaves it, and the last state with `deadlock`
(a search path has no cycle).
"""
import argparse
import re
import sys

STATE = re.compile(r'^state (\d+), [^:]+: ', re.M)
RULE = re.compile(r'^===\[ c?rl \[([^\]]+)\]', re.M)
TAIL = re.compile(r'\n(?:Maude>|Bye|[^ \n])')


def convert(text):
    starts = list(STATE.finditer(text))
    if not starts:
        sys.exit('no "state N, Sort:" in the input')
    steps = []
    for i, m in enumerate(starts):
        end = starts[i + 1].start() if i + 1 < len(starts) else len(text)
        chunk = text[m.end():end]
        r = RULE.search(chunk)
        if r:
            term, label = chunk[:r.start()], "'" + r.group(1)
        else:  # the last state: cut what Maude prints after the term
            t = TAIL.search(chunk)
            term, label = chunk[:t.start()] if t else chunk, 'deadlock'
        steps.append((int(m.group(1)), term.strip(), label))
    return steps


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('log')
    ap.add_argument('--title', default='show path')
    a = ap.parse_args()
    steps = convert(open(a.log).read())
    print(f'search {a.title}')
    print(f'states on the path: {" ".join(str(n) for n, _, _ in steps)}')
    body = ' '.join('{' + t + ', ' + l + '}' for _, t, l in steps[:-1])
    _, t, l = steps[-1]
    print('result ModelCheckResult: counterexample(' + body + ', {' + t + ', ' + l + '})')


if __name__ == '__main__':
    main()
