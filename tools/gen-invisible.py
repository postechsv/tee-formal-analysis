"""Generate the invisible-transition reduction (src/invisible-reduction.maude of the spec) from
docs/invisible-g/decisions.tsv.

Usage: python3 tools/gen-invisible.py [--src spec/src] [--decisions docs/invisible-g/decisions.tsv] [OUT]

Each rule whose label is marked G becomes an equation with the same text (rl -> eq, crl -> ceq,
top-level => -> =), in a module <MOD>-INVISIBLE that imports the rule's module and copies its
variable declarations.  OUT defaults to SRC/invisible-reduction.maude.  The hand-written header of
OUT (everything before its first module annotation) is kept; a new file gets HEAD."""
import argparse, os, re, sys, collections

HERE = os.path.dirname(os.path.abspath(__file__))
ap = argparse.ArgumentParser()
ap.add_argument('--src', default=os.path.join(HERE, '..', 'spec', 'src'))
ap.add_argument('--decisions', default=os.path.join(HERE, '..', 'docs', 'invisible-g', 'decisions.tsv'))
ap.add_argument('out', nargs='?')
args = ap.parse_args()
SRC = args.src
OUT = args.out or os.path.join(SRC, 'invisible-reduction.maude')
D = {}
for ln in open(args.decisions):
    if ln.startswith('#') or not ln.strip(): continue
    f = ln.rstrip('\n').split('\t'); D[f[0]] = f[1]
G = {l for l, v in D.items() if v == 'G'}

def strip_comments(s):
    return '\n'.join(re.sub(r'---.*$', '', ln) for ln in s.split('\n'))

def depth_cut(body, tok):
    d = 0
    for i in range(len(body)):
        ch = body[i]
        if ch in '([{': d += 1
        elif ch in ')]}': d -= 1
        elif d == 0 and body.startswith(tok, i): return i
    return -1

FILES = ['imp.maude', 'tee-app.maude', 'generic.maude', 'transient.maude', 'persistent.maude',
         'data-stream.maude', 'cryptographic.maude', 'persistent-panic.maude']
mods = collections.OrderedDict()      # mod -> (kind, vars, eqs)
for fn in FILES:
    s = strip_comments(open(f'{SRC}/{fn}').read())
    for mm in re.finditer(r'\b(omod|mod|fmod)\s+([\w-]+)\s+is\b(.*?)\bend(om|m|fm)\b', s, re.S):
        kind, mod, body = mm.group(1), mm.group(2), mm.group(3)
        eqs = []
        for r in re.finditer(r'\b(c?rl)\s*\[([^\]]*)\]\s*:(.*?)\s\.(?=[ \t]*(?:\n|$))', body, re.S):
            lab = r.group(2).strip()
            if lab not in G: continue
            text = r.group(3)
            i = depth_cut(text, '=>')
            assert i >= 0, lab
            lhs, rest = text[:i], text[i + 2:]
            lines = [ln.rstrip() for ln in (lhs.rstrip() + '\n  =' + rest).split('\n')]
            lines = [ln for ln in lines if ln.strip()]
            eqs.append((lab, ('ceq' if r.group(1) == 'crl' else 'eq'), lines))
        if eqs:
            vs = [' '.join(v.split()) + ' .' for v in re.findall(r'(?:^|\n)\s*(vars?\s[^\n]*?)\s\.(?=[ \t]*(?:\n|$))', body)]
            mods[mod] = (kind, vs, eqs)

found = {lab for _, (_, _, eqs) in mods.items() for lab, _, _ in eqs}
missing = sorted(G - found)
if missing: sys.exit('labels not found: ' + ', '.join(missing))

HEAD = """--- This file defines the invisible-transition reduction of Section 8 of the paper: rewrite rules
--- are turned into equations.  Each *-INVISIBLE module imports a behavior module and restates
--- part of its rules as equations, so importing it has an effect only through the wrapper
--- modules at the end of this file; nothing in the spec imports them.
---
--- The set of rules follows the G of the paper artifact (tee-formal-analysis, spec/src
--- *-INVISIBLE modules), rule by rule:
---   K rules: those whose artifact counterpart is in the artifact G.  Not in G: the memory
---      read (lookup) and write (assign) and the allocations (alloc, allocObj, allocA), as the
---      artifact keeps leval(loc(L)), loc(L) := V and var X as rules; op-or-true and
---      op-or-false (the artifact G has no || rule); op-minus (the artifact has no -).
---   TEE API call rules: tee-api-call, tee-api-call-accept, tee-api-call-return.
---   TEE API rules: for the API functions that have rules in the artifact G (the functions
---      MQT-TZ uses), the rules of each step that the artifact G contains, on the TA and on the
---      object side; a step that the spec splits into several rules has all of them.  Rules of
---      behavior that the artifact does not have, and the API functions without artifact G
---      rules, stay rules.
--- The mapping is recorded in analysis/mqttz/probe/results/g-audit/map/decisions.tsv of
--- tee-formal-analysis.
---
--- The feature INVISIBLE (mk/features.mk, off by default) keeps this file out of a build.
--- The equations are generated copies of the rules: when a rule changes, regenerate them.
"""
if os.path.exists(OUT):
    old = open(OUT).read()
    i = old.find('--- @kind')
    if i > 0:
        HEAD = old[:i].rstrip('\n') + '\n'
out = [HEAD]
api_mods, imp_mods, call_mods = [], [], []
for mod, (kind, vs, eqs) in mods.items():
    k = 'mod' if kind == 'mod' else 'omod'
    out.append('--- @kind behavior\n--- @feature invisible')
    out.append(f'{k} {mod}-INVISIBLE is\n  pr {mod} .\n')
    out += ['  ' + v for v in vs]
    out.append('')
    for lab, e, lines in eqs:
        out.append(f'  --- {lab}')
        out.append(f'  {e}')
        out += ['  ' + ln if not ln.startswith('  ') else ln for ln in lines]
        out.append('  .\n')
    out.append('end' + ('m' if k == 'mod' else 'om') + '\n')
    (imp_mods if mod == 'IMP-SEMANTICS' else call_mods if mod == 'TRUST-APP-IMP-BEHAVIOR' else api_mods).append(mod + '-INVISIBLE')
for name, ms in (('INVISIBLE-REDUCTION', api_mods), ('IMP-INVISIBLE-REDUCTION', imp_mods),
                 ('TEE-API-CALL-INVISIBLE-REDUCTION', call_mods)):
    out.append('--- @kind assembly\n--- @feature invisible')
    out.append(f'mod {name} is\n' + ''.join(f'  pr {m} .\n' for m in ms) + 'endm\n')
txt = '\n'.join(out)
bad = [ln for ln in txt.split('\n') if ln.lstrip().startswith('--- (')]
if bad: sys.exit('comment line starting with "--- (": ' + bad[0])
open(OUT, 'w').write(txt)
print('modules', len(mods), 'equations', sum(len(e) for _, _, e in mods.values()))
