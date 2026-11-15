#!/usr/bin/env python3
"""drop-class-attribute: drop a class attribute from the left-hand sides of spec rules (rewritten in place).

Usage
    python3 tools/build/drop-class-attribute.py SRC_DIR CASE.toml

The [drop-class-attribute] table of CASE.toml says which rules no longer require an attribute value
on the left-hand side; several are written as [[drop-class-attribute]] (an array of tables):

    [drop-class-attribute]
    class          = "TAKernel"            # objects of this class or of a subclass
    attribute      = "status : normal"     # the attribute the left-hand side no longer requires
    affected-rules = ["*"]                 # rule labels (globs)
    excluded-rules = ["alloc-oper-*"]      # rule labels (globs) left as they are

The change is syntactic.  In a rule whose label matches `affected-rules` and no pattern of
`excluded-rules`, and whose left-hand side has an object of the class (or a subclass) with the
attribute value of `attribute` (possibly sort-qualified: (normal).AppStatus for normal), that
attribute is removed from the object, with its comma; the rule then fires whatever the value of the
attribute is.  The label, the ---@dmc directives and the number of rules are unchanged.  Every
pattern of `affected-rules` and `excluded-rules` must match a rule label.

tools/build/transform.mk runs this on the stage (DROP_ATTR=ANALYSIS.toml) before the ghosts are composed.
"""

import fnmatch
import importlib.util
import os
import re
import sys
import tomllib

KEYS = {'class', 'attribute', 'affected-rules', 'excluded-rules'}


def load_gen():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'dmc', 'gen-dmc.py')
    spec = importlib.util.spec_from_file_location('gen_dmc', path)
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    return gen


class DropError(Exception):
    pass


def attr_value(text):
    """'status : normal' -> ('status', 'normal')."""
    m = re.match(r'^\s*([\w\-]+)\s*:\s*(\S.*?)\s*$', text)
    if not m:
        raise DropError('not an attribute "name : value": %r' % text)
    return m.group(1), m.group(2)


def same_value(written, value):
    """written is value, possibly sort-qualified: (normal).AppStatus for normal."""
    w = written.strip()
    return w == value or re.fullmatch(r'\(\s*%s\s*\)\.[\w\-{},]+' % re.escape(value), w) is not None


def entries(path):
    with open(path, 'rb') as fh:
        data = tomllib.load(fh)
    tables = data.get('drop-class-attribute', [])
    if isinstance(tables, dict):
        tables = [tables]
    out = []
    for i, t in enumerate(tables):
        where = '%s: [drop-class-attribute] #%d' % (path, i + 1)
        unknown = sorted(set(t) - KEYS)
        if unknown:
            raise DropError('%s: unknown key %s' % (where, ', '.join(unknown)))
        for k in ('class', 'attribute', 'affected-rules'):
            if k not in t:
                raise DropError('%s: no %s' % (where, k))
        name, value = attr_value(t['attribute'])
        out.append(dict(where=where, cls=t['class'], attr=name, value=value,
                        rules=list(t['affected-rules']), exc=list(t.get('excluded-rules', []))))
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


def drop(gen, src, e, files, subs):
    classes = closure(e['cls'], subs)
    labels, done = set(), []
    val = r'%s\s*:\s*(?:\(\s*%s\s*\)\.[\w\-{},]+|%s)(?![\w\-.(])' % (
        re.escape(e['attr']), re.escape(e['value']), re.escape(e['value']))
    attr = r'(?<![\w\-])' + val
    # the attribute with the comma after it, else with the comma before it, else alone
    forms = [re.compile(attr + r'\s*,\s*'), re.compile(r'\s*,\s*' + attr), re.compile(r'\s*' + attr)]
    for f, fi in files:
        edits = []      # (first line, last line, new lines)
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
                raise DropError('%s:%d: [%s]: %d objects of the left-hand side have %s : %s; '
                                'only one of class %s is supported'
                                % (f, u.line, lab, hits + others, e['attr'], e['value'], e['cls']))
            raw = [fi.lines[k][0] for k in range(u.start, u.end + 1)]
            text = '\n'.join(raw)
            arrow = text.find('=>')
            lhs, rest = text[:arrow], text[arrow:]
            if len(re.findall(attr, lhs)) != 1:
                raise DropError('%s:%d: [%s]: cannot find %s : %s once in the source text'
                                % (f, u.line, lab, e['attr'], e['value']))
            for rx in forms:
                new_lhs, n = rx.subn('', lhs, count=1)
                if n:
                    break
            new_lhs = re.sub(r'\|\s+>', '| >', new_lhs)
            edits.append((u.start, u.end, (new_lhs + rest).split('\n')))
            done.append('%s:%d [%s]' % (f, u.line, lab))
        if edits:
            eol = fi.eol
            lines = [t + nl for t, nl in fi.lines]
            for first, last, new in sorted(edits, reverse=True):
                nl = fi.lines[last][1] or eol
                lines[first:last + 1] = [t + eol for t in new[:-1]] + [new[-1] + nl]
            with open(os.path.join(src, f), 'w', encoding='utf-8', newline='') as fh:
                fh.write(''.join(lines))
    for p in e['rules'] + e['exc']:
        if not any(fnmatch.fnmatchcase(lab, p) for lab in labels):
            raise DropError('%s: no rule label matches %s' % (e['where'], p))
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
            done = drop(gen, src, e, files, subs)
            print('  drop-class-attribute: %s : %s dropped from %d rules (%s)'
                  % (e['attr'], e['value'], len(done), os.path.relpath(path)))
    except (DropError, gen.GenError) as ex:
        sys.stderr.write('drop-class-attribute: error: %s\n' % ex)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
