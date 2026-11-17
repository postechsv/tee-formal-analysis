#!/usr/bin/env python3
"""drop-rules: remove rules of the spec from a build, by label (rewritten in place).

Usage
    python3 tools/build/drop-rules.py [--spec-src SPEC_DIR] SRC_DIR ANALYSIS.toml

The list drop-rules = ["label", ...] of the analysis file names the rules that the analysis leaves
out of the spec: each rule (rl or crl) with one of these labels is removed from the loaded files of
SRC_DIR.  An analysis does so to model an assumption that differs from the spec, and says why in a
comment next to the list (e.g. mqttz: a panicked TA blocks its client, as in the paper artifact,
where the spec answers TEE_ERROR_TARGET_DEAD).  Every label must name a rule; with --spec-src
(the spec checkout, whose rules of every feature give the labels), a label of a rule that a feature
left out of this build is skipped with a warning.

tools/build/transform.mk runs this on the stage (DROP_RULES=ANALYSIS.toml) first, before the
dropped class attributes and the ghosts.
"""

import importlib.util
import os
import re
import sys
import tomllib


def load_gen():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'dmc', 'gen-dmc.py')
    spec = importlib.util.spec_from_file_location('gen_dmc', path)
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    return gen


def main(argv):
    gen = load_gen()
    spec_labels = None
    if argv[:1] == ['--spec-src'] and len(argv) >= 2:
        spec_labels, argv = gen.spec_rule_labels(argv[1]), argv[2:]
    if len(argv) != 2:
        sys.stderr.write(__doc__)
        return 2
    src, path = argv
    with open(path, 'rb') as fh:
        labels = tomllib.load(fh).get('drop-rules', [])
    if not (isinstance(labels, list) and all(isinstance(x, str) for x in labels)):
        sys.stderr.write('drop-rules: error: %s: drop-rules must be a list of rule labels\n' % path)
        return 1
    wanted, found = set(labels), set()
    try:
        for f in gen.load_order(src):
            fpath = os.path.join(src, f)
            with open(fpath, encoding='utf-8', newline='') as fh:
                fi = gen.FileInfo(f, fh.read())
            fi.units, fi.kinds = gen.scan_units([t for t, _ in fi.lines], f)
            gone = set()
            for u in fi.units:
                m = re.match(r'^c?rl\s+\[([^\]]+)\]\s*:', u.text) if u.kind == 'stmt' else None
                if m and m.group(1).strip() in wanted:
                    found.add(m.group(1).strip())
                    gone.update(range(u.start, u.end + 1))
                    print('  drop-rules: [%s] %s:%d' % (m.group(1).strip(), f, u.line))
            if gone:
                with open(fpath, 'w', encoding='utf-8', newline='') as fh:
                    fh.write(''.join(t + nl for i, (t, nl) in enumerate(fi.lines) if i not in gone))
    except gen.GenError as ex:
        sys.stderr.write('drop-rules: error: %s\n' % ex)
        return 1
    for lab in labels:
        if lab not in found:
            err = gen.unmatched_label(lab, spec_labels)
            if err:
                sys.stderr.write('drop-rules: error: %s: %s\n' % (path, err))
                return 1
            print('  drop-rules: warning: %s: %s matches only rules left out of this build' % (path, lab))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
