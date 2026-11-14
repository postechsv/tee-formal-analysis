#!/usr/bin/env python3
"""ghost: compose ghost state with the rules of a spec source tree (rewritten in place).

Usage
    python3 tools/ghost.py SRC_DIR GHOST_FILE [GHOST_FILE ...]

A GHOST_FILE is either a ghost module (.maude), whose format and composition are described in
tools/gen-dmc.py (section "ghost composition"), or a case-study file (.toml) whose [ghost] tables
declare ghost attributes of spec objects:

    [ghost.TrustedApp.running]
    init        = false                         # value when an object of the class is created
    true-after  = ["handle-invoke-ta", ...]     # rule labels (globs allowed) that set it to true
    false-after = ["handle-invoke-ta-finish", ...]

    [[ghost.TrustedApp.counter.set]]            # general form: any value term, any sort
    after = ["tee-api-call-accept"]
    value = "s(C)"                              # may use the old value of the attribute as OLD

`true-after`/`false-after` are short for `set` entries with the values true/false; the sort is
`sort = "..."`, else Bool when init is a boolean.  A label must name a rule of SRC_DIR; a glob must
match at least one.  A rule gets the ghost attribute updates of all patterns that match its label;
its left-hand side must have exactly one object of the class.  A rule whose right-hand side has an
object of the class that its left-hand side does not have creates it, and gets the init values.

The .toml file is compiled to a ghost module (written to <SRC_DIR>/../../ghost/<name>.maude when that
is a build stage, for inspection; else to a temporary directory) and composed like a .maude ghost file.

The Makefile runs this on the stage (make GHOST=...), before the plain copy (DMC=0) or gen-dmc
(DMC=1).
"""

import fnmatch
import importlib.util
import os
import re
import sys
import tempfile
import tomllib


def load_gen():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'gen-dmc.py')
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


def compile_toml(gen, src, path):
    """The ghost module text for the [ghost] tables of path, and its file name stem."""
    with open(path, 'rb') as fh:
        data = tomllib.load(fh)
    ghost = data.get('ghost')
    if not ghost:
        raise gen.GenError('%s: no [ghost] table' % path)
    rules, classes = scan_rules(gen, src)
    labels = sorted({lab for lab, *_ in rules})
    name = os.path.splitext(os.path.basename(path))[0]
    mod = re.sub(r'[^A-Za-z0-9]+', '-', name).upper() + '-GHOST'

    attrs = {}        # (class, attr) -> (sort, init)
    updates = {}      # label -> {(class, attr): value}
    for cls, table in ghost.items():
        if cls not in classes:
            raise gen.GenError('%s: class %s is not declared in %s' % (path, cls, src))
        for attr, spec in table.items():
            if 'init' not in spec:
                raise gen.GenError('%s: ghost.%s.%s has no init' % (path, cls, attr))
            init = spec['init']
            sort = spec.get('sort') or ('Bool' if isinstance(init, bool) else None)
            if sort is None:
                raise gen.GenError('%s: ghost.%s.%s needs a sort' % (path, cls, attr))
            attrs[(cls, attr)] = (sort, toml_value(init))
            sets = [(p, 'true') for p in spec.get('true-after', [])] + \
                   [(p, 'false') for p in spec.get('false-after', [])]
            for entry in spec.get('set', []):
                sets += [(p, str(entry['value'])) for p in entry['after']]
            for pat, val in sets:
                hit = [lab for lab in labels if fnmatch.fnmatchcase(lab, pat)]
                if not hit:
                    raise gen.GenError('%s: ghost.%s.%s: no rule label matches %s' % (path, cls, attr, pat))
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

    lines = ['--- Compiled from %s by tools/ghost.py.' % os.path.relpath(path),
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
    if len(argv) < 2:
        sys.stderr.write(__doc__)
        return 2
    gen = load_gen()
    src = argv[0]
    paths = []
    try:
        for p in argv[1:]:
            if p.endswith('.toml'):
                name, text = compile_toml(gen, src, p)
                stage = os.path.dirname(os.path.abspath(src))
                out_dir = (os.path.join(os.path.dirname(stage), 'ghost') if os.path.basename(stage) == '.stage'
                           else tempfile.mkdtemp(prefix='ghost-'))
                os.makedirs(out_dir, exist_ok=True)
                out = os.path.join(out_dir, name + '.maude')
                with open(out, 'w', encoding='utf-8') as fh:
                    fh.write(text)
                print('  ghost: %s -> %s' % (p, out))
                paths.append(out)
            else:
                paths.append(p)
        report = gen.compose_ghosts(src, paths)
    except gen.GenError as ex:
        sys.stderr.write('ghost: error: %s\n' % ex)
        return 1
    for line in report:
        print('  ghost: %s' % line)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
