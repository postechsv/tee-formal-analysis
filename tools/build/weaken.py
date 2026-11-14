#!/usr/bin/env python3
"""weaken: weaken rule conditions of a spec source tree (rewritten in place).

Usage
    python3 tools/build/weaken.py SRC_DIR CASE.toml

The [weaken-rule-condition] table of CASE.toml says which rules also fire on another attribute
value; several weakenings are written as [[weaken-rule-condition]] (an array of tables), one per
weakening:

    [[weaken-rule-condition]]
    class      = "TAKernel"                # objects of this class or of a subclass
    condition  = "status : normal"         # an attribute the left-hand side of the rule requires
    allow-also = "status : outOfMemory"    # the rule also fires on this value
    rules      = ["*"]                     # rule labels (globs)
    except     = ["alloc-oper-*"]          # rule labels (globs) left as they are

A rule is weakened when its label matches `rules` and no pattern of `except`, and its left-hand side
has an object of the class (or a subclass) with the attribute value of `condition`; the value may
be written with a sort qualification, (normal).AppStatus for normal.  The rule is kept, and a copy
of it, with the same label and ---@dmc directives, is added after it with the value of
`allow-also` in place of that of `condition`.  Every pattern of `rules` and `except` must match a
rule label.

The Makefile runs this on the stage (make WEAKEN=CASE.toml) before the ghosts are composed, so a
copy gets the ghost updates and the invisible-reduction equations of its label.
"""

import fnmatch
import importlib.util
import os
import re
import sys
import tomllib

KEYS = {'class', 'condition', 'allow-also', 'rules', 'except'}


def load_gen():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'dmc', 'gen-dmc.py')
    spec = importlib.util.spec_from_file_location('gen_dmc', path)
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    return gen


class WeakenError(Exception):
    pass


def attr_value(text):
    """'status : normal' -> ('status', 'normal')."""
    m = re.match(r'^\s*([\w\-]+)\s*:\s*(\S.*?)\s*$', text)
    if not m:
        raise WeakenError('not an attribute "name : value": %r' % text)
    return m.group(1), m.group(2)


def same_value(written, value):
    """written is value, possibly sort-qualified: (normal).AppStatus for normal."""
    w = written.strip()
    return w == value or re.fullmatch(r'\(\s*%s\s*\)\.[\w\-{},]+' % re.escape(value), w) is not None


def entries(path):
    with open(path, 'rb') as fh:
        data = tomllib.load(fh)
    tables = data.get('weaken-rule-condition', [])
    if isinstance(tables, dict):
        tables = [tables]
    out = []
    for i, t in enumerate(tables):
        where = '%s: [[weaken-rule-condition]] #%d' % (path, i + 1)
        unknown = sorted(set(t) - KEYS)
        if unknown:
            raise WeakenError('%s: unknown key %s' % (where, ', '.join(unknown)))
        for k in ('class', 'condition', 'allow-also', 'rules'):
            if k not in t:
                raise WeakenError('%s: no %s' % (where, k))
        name, value = attr_value(t['condition'])
        name2, value2 = attr_value(t['allow-also'])
        if name2 != name:
            raise WeakenError('%s: condition and allow-also name different attributes (%s, %s)'
                              % (where, name, name2))
        out.append(dict(where=where, cls=t['class'], attr=name, value=value, also=value2,
                        rules=list(t['rules']), exc=list(t.get('except', []))))
    return out


def scan(gen, src):
    """The loaded files as [(file, FileInfo)], and {class: set of its direct subclasses}."""
    files, subs = [], {}
    for f in gen.load_order(src):
        with open(os.path.join(src, f), encoding='utf-8', newline='') as fh:
            fi = gen.FileInfo(f, fh.read())
        fi.units, fi.kinds = gen.scan_units([t for t, _ in fi.lines], f)
        for u in fi.units:
            if u.kind == 'stmt' and u.text.split()[0] in ('subclass', 'subclasses'):
                m = re.match(r'^subclass(?:es)?\s+(.*?)\s*<\s*(.*?)\s*\.?\s*$', u.text)
                if m:
                    for sup in m.group(2).split():
                        for sub in m.group(1).split():
                            subs.setdefault(sup, set()).add(sub)
        files.append((f, fi))
    return files, subs


def closure(cls, subs):
    out, todo = set(), [cls]
    while todo:
        c = todo.pop()
        if c not in out:
            out.add(c)
            todo.extend(subs.get(c, ()))
    return out


def matches(label, pats):
    return any(fnmatch.fnmatchcase(label, p) for p in pats)


def weaken(gen, src, e, files, subs):
    classes = closure(e['cls'], subs)
    labels, done = set(), []
    value_re = re.compile(r'(?<![\w\-])%s(\s*:\s*)(\(\s*%s\s*\)\.[\w\-{},]+|%s)(?![\w\-.(])'
                          % (re.escape(e['attr']), re.escape(e['value']), re.escape(e['value'])))
    for f, fi in files:
        inserts = []    # (line index after which, lines)
        for u in fi.units:
            if u.kind != 'stmt' or u.text.split()[0] not in ('rl', 'crl'):
                continue
            r = gen.parse_rule(u.text)
            lab = r['label']
            if not lab:
                continue
            labels.add(lab)
            if not matches(lab, e['rules']) or matches(lab, e['exc']):
                continue
            hits, others = 0, 0
            for it in gen.config_items(r['lhs']):
                o = gen.obj_parts(it)
                if o is None:
                    continue
                for a, v in o[2]:
                    if a == e['attr'] and same_value(v, e['value']):
                        if o[1] in classes:
                            hits += 1
                        else:
                            others += 1
            if hits == 0:
                continue
            if others or hits > 1:
                raise WeakenError('%s:%d: [%s]: %d objects of the left-hand side have %s : %s; '
                                  'only one of class %s is supported'
                                  % (f, u.line, lab, hits + others, e['attr'], e['value'], e['cls']))
            raw = [fi.lines[k][0] for k in range(u.start, u.end + 1)]
            text = '\n'.join(raw)
            arrow = text.find('=>')
            lhs, rest = text[:arrow], text[arrow:]
            new_lhs, n = value_re.subn(lambda m: e['attr'] + m.group(1) + e['also'], lhs)
            if n != 1:
                raise WeakenError('%s:%d: [%s]: cannot find %s : %s in the source text'
                                  % (f, u.line, lab, e['attr'], e['value']))
            dirs = [fi.lines[k][0] for k in range(u.start - len(u.dmc), u.start)]
            ind = re.match(r'\s*', raw[0]).group(0)
            note = '%s--- weaken-rule-condition: a copy of [%s] that also fires on %s : %s' % (
                ind, lab, e['attr'], e['also'])
            inserts.append((u.end, [''] + [note] + dirs + (new_lhs + rest).split('\n')))
            done.append('%s:%d [%s]' % (f, u.line, lab))
        if inserts:
            eol = fi.eol
            lines = [t + nl for t, nl in fi.lines]
            for after, new in sorted(inserts, reverse=True):
                lines[after + 1:after + 1] = [t + eol for t in new]
            with open(os.path.join(src, f), 'w', encoding='utf-8', newline='') as fh:
                fh.write(''.join(lines))
    for p in e['rules'] + e['exc']:
        if not any(fnmatch.fnmatchcase(lab, p) for lab in labels):
            raise WeakenError('%s: no rule label matches %s' % (e['where'], p))
    return done


def main(argv):
    if len(argv) != 2:
        sys.stderr.write(__doc__)
        return 2
    src, path = argv
    gen = load_gen()
    try:
        for e in entries(path):
            files, subs = scan(gen, src)
            done = weaken(gen, src, e, files, subs)
            print('  weaken: %s : %s also allows %s : %s in %d rules (%s)'
                  % (e['attr'], e['value'], e['attr'], e['also'], len(done), os.path.relpath(path)))
    except (WeakenError, gen.GenError) as ex:
        sys.stderr.write('weaken: error: %s\n' % ex)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
