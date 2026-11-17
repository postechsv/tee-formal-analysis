#!/usr/bin/env python3
"""ghost: compose ghost state with the rules of a spec source tree (rewritten in place).

Usage
    python3 tools/build/ghost.py [--spec-src SPEC_DIR] SRC_DIR GHOST_FILE [GHOST_FILE ...]

A GHOST_FILE is either a ghost module (.maude), whose format and composition are described in
tools/dmc/gen-dmc.py (section "ghost composition"), or a case-study file (.toml) whose [ghost] tables
declare ghost attributes of spec objects, one table per attribute:

    [ghost]
    var           = "running"                     # the attribute
    class         = "TrustedApp"                  # the spec class that gets it
    initial-value = false                         # value when an object of the class is created
    true-after    = ["handle-invoke-ta", ...]     # rule labels (globs allowed) that set it to true
    false-after   = ["handle-invoke-ta-finish", ...]

Several attributes are written as [[ghost]] (an array of tables), one per attribute.  General form:

    [[ghost]]
    var           = "counter"
    class         = "TrustedApp"
    initial-value = "0"
    sort          = "Nat"
    [[ghost.set]]                                 # any value term, any sort
    after = ["tee-api-call-accept"]
    value = "s(OLD)"                              # may use the old value of the attribute as OLD

`true-after`/`false-after` are short for `set` entries with the values true/false; the sort is
`sort = "..."`, else Bool when initial-value is a boolean.  A label must name a rule of SRC_DIR; a
glob must match at least one (with --spec-src SPEC_DIR, the spec checkout, whose rules of every
feature give the labels, a pattern that matches only rules of features left out of this build is
skipped with a warning).  A rule gets the ghost attribute updates of all patterns that match its
label; its left-hand side must have exactly one object of the class.  A rule whose right-hand side
has an object of the class that its left-hand side does not have creates it, and gets the initial
values.

The .toml file is compiled to a ghost module, written to a temporary directory, and composed like a
.maude ghost file.

tools/build/transform.mk runs this on the stage (GHOST=...), before the plain copy (DMC=0) or gen-dmc
(DMC=1).
"""

import fnmatch
import importlib.util
import os
import re
import sys
import tempfile
import tomllib


def split_spec_src(argv, gen):
    """argv without --spec-src DIR, and the rule labels of the spec checkout DIR (None without it)."""
    if argv[:1] == ['--spec-src'] and len(argv) >= 2:
        return argv[2:], gen.spec_rule_labels(argv[1])
    return argv, None


def load_gen():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'dmc', 'gen-dmc.py')
    spec = importlib.util.spec_from_file_location('gen_dmc', path)
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    return gen


def scan_rules(gen, src):
    """[(label, file, line, rule dict, {var: sort})] of every labeled rule of the loaded files, and
    {class: module} of the class declarations."""
    rules, classes = [], {}
    for f in gen.load_order(src):
        with open(os.path.join(src, f), encoding='utf-8', newline='') as fh:
            fi = gen.FileInfo(f, fh.read())
        fi.units, fi.kinds = gen.scan_units([t for t, _ in fi.lines], f)
        head, minfo = None, None
        for u in fi.units:
            if u.kind == 'head':
                head = u if u.text.split()[0] != 'view' else None
                minfo = gen.module_info(fi, fi.units, head) if head is not None else None
                continue
            if u.kind != 'stmt' or head is None:
                continue
            w = u.text.split()[0]
            if w == 'class':
                m = re.match(r'^class\s+([^\s|.]+)', u.text)
                classes.setdefault(m.group(1), gen.mod_name_of_head(head.text))
            elif w in ('rl', 'crl'):
                r = gen.parse_rule(u.text)
                if r['label']:
                    rules.append((r['label'], f, u.line, r, minfo[0]))
    return rules, classes


def toml_value(v):
    if isinstance(v, bool):
        return 'true' if v else 'false'
    return str(v)


GHOST_KEYS = {'var', 'class', 'initial-value', 'sort', 'true-after', 'false-after', 'set'}


def ghost_entries(data, path):
    """The ghost attributes of a case-study manifest (its [ghost] table or [[ghost]] tables), as
    [(class, attr, entry)].  Raises ValueError on a malformed entry."""
    ghost = data.get('ghost', [])
    entries = [ghost] if isinstance(ghost, dict) else ghost
    out, seen = [], set()
    for i, e in enumerate(entries):
        where = '%s: [ghost] #%d' % (path, i + 1)
        if not isinstance(e, dict):
            raise ValueError('%s: not a table' % where)
        unknown = sorted(set(e) - GHOST_KEYS)
        if unknown:
            raise ValueError('%s: unknown key %s (keys: %s)' % (where, ', '.join(unknown),
                             ', '.join(sorted(GHOST_KEYS))))
        for k in ('var', 'class', 'initial-value'):
            if k not in e:
                raise ValueError('%s: no %s' % (where, k))
        key = (e['class'], e['var'])
        if key in seen:
            raise ValueError('%s: ghost %s.%s declared twice' % (where, *key))
        seen.add(key)
        out.append((e['class'], e['var'], e))
    return out


def compile_toml(gen, src, path, spec_labels=None):
    """The ghost module text for the [ghost] tables of path, and its file name stem."""
    with open(path, 'rb') as fh:
        data = tomllib.load(fh)
    try:
        ghost = ghost_entries(data, path)
    except ValueError as ex:
        raise gen.GenError(str(ex))
    if not ghost:
        raise gen.GenError('%s: no [ghost] table' % path)
    rules, classes = scan_rules(gen, src)
    labels = sorted({lab for lab, *_ in rules})
    name = os.path.splitext(os.path.basename(path))[0]
    mod = re.sub(r'[^A-Za-z0-9]+', '-', name).upper() + '-GHOST'

    attrs = {}        # (class, attr) -> (sort, init)
    updates = {}      # label -> {(class, attr): value}
    for cls, attr, spec in ghost:
        if cls not in classes:
            raise gen.GenError('%s: class %s is not declared in %s' % (path, cls, src))
        init = spec['initial-value']
        sort = spec.get('sort') or ('Bool' if isinstance(init, bool) else None)
        if sort is None:
            raise gen.GenError('%s: ghost %s.%s needs a sort' % (path, cls, attr))
        attrs[(cls, attr)] = (sort, toml_value(init))
        sets = [(p, 'true') for p in spec.get('true-after', [])] + \
               [(p, 'false') for p in spec.get('false-after', [])]
        for entry in spec.get('set', []):
            sets += [(p, str(entry['value'])) for p in entry['after']]
        for pat, val in sets:
            hit = [lab for lab in labels if fnmatch.fnmatchcase(lab, pat)]
            if not hit:
                err = gen.unmatched_label(pat, spec_labels)
                if err:
                    raise gen.GenError('%s: ghost %s.%s: %s' % (path, cls, attr, err))
                print('  ghost: warning: %s: ghost %s.%s: %s matches only rules left out of this build'
                      % (path, cls, attr, pat))
            for lab in hit:
                old = updates.setdefault(lab, {}).get((cls, attr))
                if old is not None and old != val:
                    raise gen.GenError('%s: rule [%s] would set %s.%s to both %s and %s'
                                       % (path, lab, cls, attr, old, val))
                updates[lab][(cls, attr)] = val

    # creation sites: an object of a ghost class on the right-hand side whose identifier is not an
    # object of the left-hand side
    gclasses = sorted({c for c, _ in attrs})
    creates = {}      # label -> [(oid, class, {var: sort})]
    for lab, f, line, r, mvars in rules:
        lobj = [gen.obj_parts(it) for it in gen.config_items(r['lhs'])]
        loids = {gen.norm(o[0]) for o in lobj if o is not None}
        for it in gen.config_items(r['rhs']):
            o = gen.obj_parts(it)
            if o is not None and o[1] in gclasses and gen.norm(o[0]) not in loids:
                toks = set(gen.IDENT_TOK_RE.findall(o[0]))
                creates.setdefault(lab, []).append((o[0], o[1], {v: s for v, s in mvars.items() if v in toks}))

    lines = ['--- Compiled from %s by tools/build/ghost.py.' % os.path.relpath(path),
             'omod %s is' % mod]
    for c in gclasses:
        lines.append('  pr %s .' % classes[c])
    carrier = '%s-ATTRS' % mod
    lines.append('  class %s | %s .' % (carrier, ' , '.join(
        '%s : %s' % (a, attrs[(c, a)][0]) for c, a in sorted(attrs))))
    decls, rules_out = {}, []
    for lab in sorted(set(updates) | set(creates)):
        if lab in updates and lab in creates:
            raise gen.GenError('%s: rule [%s] both creates and updates a ghost object' % (path, lab))
    for lab, ups in sorted(updates.items()):
        for c in sorted({c for c, _ in ups}):
            mine = sorted((a, v) for (cc, a), v in ups.items() if cc == c)
            olds = []
            for a, _ in mine:
                vn = 'OLD-%s' % re.sub(r'[^A-Za-z0-9]', '-', a).upper()
                decls[vn] = attrs[(c, a)][0]
                olds.append((a, vn))
            lhs = '< G-OBJ : %s | %s >' % (c, ' , '.join('%s : %s' % av for av in olds))
            rhs = '< G-OBJ : %s | %s >' % (c, ' , '.join(
                '%s : %s' % (a, re.sub(r'\bOLD\b', dict(olds)[a], v)) for a, v in mine))
            rules_out.append('  rl [%s] :\n    %s\n    =>\n    %s .' % (lab, lhs, rhs))
    decls['G-OBJ'] = 'Oid'
    for lab, objs in sorted(creates.items()):
        rhs = []
        for oid, c, vs in objs:
            decls.update(vs)
            rhs.append('< %s : %s | %s >' % (oid, c, ' , '.join(
                '%s : %s' % (a, attrs[(cc, a)][1]) for cc, a in sorted(attrs) if cc == c)))
        rules_out.append('  rl [%s] :\n    none\n    =>\n    %s .' % (lab, '\n    '.join(rhs)))
    for v, s in sorted(decls.items()):
        lines.append('  var %s : %s .' % (v, s))
    lines.append('')
    lines += [r + '\n' for r in rules_out]
    lines.append('endom')
    return name, '\n'.join(lines) + '\n'


def main(argv):
    gen = load_gen()
    argv, spec_labels = split_spec_src(argv, gen)
    if len(argv) < 2:
        sys.stderr.write(__doc__)
        return 2
    src = argv[0]
    paths = []
    tmp = tempfile.TemporaryDirectory(prefix='ghost-')
    try:
        for p in argv[1:]:
            if p.endswith('.toml'):
                name, text = compile_toml(gen, src, p, spec_labels)
                out = os.path.join(tmp.name, name + '.maude')
                with open(out, 'w', encoding='utf-8') as fh:
                    fh.write(text)
                paths.append(out)
            else:
                paths.append(p)
        report = gen.compose_ghosts(src, paths)
    except gen.GenError as ex:
        sys.stderr.write('ghost: error: %s\n' % ex)
        return 1
    finally:
        tmp.cleanup()
    for line in report:
        print('  ghost: %s' % line)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
