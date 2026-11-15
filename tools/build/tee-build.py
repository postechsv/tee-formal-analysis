#!/usr/bin/env python3
"""tee-build: build an analysis of a case study.

Usage
    python3 tools/build/tee-build.py CASE ANALYSIS [--spec DIR]
    (make ANALYSIS in CASE/, with the Makefile of the case study)
    python3 tools/build/tee-build.py --list CASE      (the analyses of CASE)

CASE/CASE.toml says what the analyzed system is:
    [spec]            the specification: repo (a git URL) and rev (a commit, branch or tag), and
                      [spec.features] (FEATURE = 0 or 1; every API feature of the spec is on by default)
    [ta.KEY]          a trusted application preprocessed from its C source (tools/lang/preprocess.py)
    [ra.KEY]          a rich application (the client of the TAs) preprocessed the same way
and how it is analyzed: every other top-level table [ANALYSIS] is an analysis, with
    mode              plain, dmc (DM-Check build) or m2l (maude2lean build); default plain
    [ANALYSIS.drop-class-attribute]  class attributes dropped from rule left-hand sides
                      (tools/build/drop-class-attribute.py)
    [ANALYSIS.ghost]  ghost attributes of spec objects (tools/build/ghost.py)
    [ANALYSIS.invisible]  the invisible-transition reduction: the rules turned into equations
                      (tools/build/gen-invisible.py); without it, there is no reduction
The paths in CASE.toml are relative to it.  The transforms read the tables of the analysis from
build/CASE-ANALYSIS/ANALYSIS.toml, which is written from them.

The spec revision is fetched into the cache build/spec/ (build/spec/repos/ holds a bare clone per
repo, build/spec/<commit>/ the tree of a commit), or --spec DIR names a checkout to use instead.  It
is built and transformed by tools/build/transform.mk into build/CASE-ANALYSIS/, and CASE/models/ANALYSIS/ is
then written from scratch with the final model, which loads on its own:
    src/          the spec, built and transformed
    core/         a copy of CASE/core/, the model files written by hand
    ta/, ra/      the preprocessed TAs and RAs
    model.maude   loads src/main, core/main, the TAs and the RAs
    main.maude    loads model.maude and core/cmd/main.maude, the entry module of the analyses
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'lang'))
import preprocess  # noqa: E402

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
SPEC_CACHE = os.path.join(ROOT, 'build', 'spec')
MODES = ('plain', 'dmc', 'm2l')
SYSTEM_KEYS = ('spec', 'ta', 'ra')


class BuildError(Exception):
    pass


def git(*args, cwd=None):
    r = subprocess.run(['git'] + list(args), cwd=cwd, capture_output=True, text=True)
    if r.returncode:
        raise BuildError('git %s: %s' % (' '.join(args), (r.stderr or r.stdout).strip()))
    return r.stdout.strip()


def fetch_spec(repo, rev):
    """The tree of rev of repo in the cache, and its commit.  A full commit id already in the
    cache is not fetched again; a branch or a tag is."""
    bare = os.path.join(SPEC_CACHE, 'repos', hashlib.sha1(repo.encode()).hexdigest()[:12] + '.git')
    if not os.path.isdir(bare):
        os.makedirs(os.path.dirname(bare), exist_ok=True)
        git('init', '-q', '--bare', bare)
        git('remote', 'add', 'origin', repo, cwd=bare)
    commit = None
    if re.fullmatch(r'[0-9a-f]{40}', rev):
        try:
            commit = git('rev-parse', '--verify', '-q', rev + '^{commit}', cwd=bare)
        except BuildError:
            commit = None
    if commit is None:
        print('tee-build: fetching %s %s' % (repo, rev))
        git('fetch', '-q', '--depth', '1', 'origin', rev, cwd=bare)
        commit = git('rev-parse', 'FETCH_HEAD^{commit}', cwd=bare)
    tree = os.path.join(SPEC_CACHE, commit)
    if not os.path.exists(os.path.join(tree, '.complete')):
        shutil.rmtree(tree, ignore_errors=True)
        os.makedirs(tree)
        archive = subprocess.Popen(['git', 'archive', commit], cwd=bare, stdout=subprocess.PIPE)
        untar = subprocess.run(['tar', '-x', '-C', tree], stdin=archive.stdout)
        archive.stdout.close()
        if archive.wait() or untar.returncode:
            raise BuildError('cannot extract %s of %s' % (commit, repo))
        open(os.path.join(tree, '.complete'), 'w').close()
    return tree, commit


def spec_features(spec_dir, settings):
    """FEATURE=VALUE for every API feature of the spec's features.mk (on unless settings turn it
    off); INVISIBLE is the reduction, set by the analysis."""
    with open(os.path.join(spec_dir, 'features.mk'), encoding='utf-8') as fh:
        m = re.search(r'^FEATURES\s*:=\s*(.*)$', fh.read(), re.MULTILINE)
    names = [f for f in m.group(1).split() if f != 'INVISIBLE']
    unknown = sorted(set(settings) - set(names))
    if unknown:
        raise BuildError('[spec.features]: not a feature of the spec: %s' % ', '.join(unknown))
    return {f: int(settings.get(f, 1)) for f in names}


def load(path):
    with open(path, 'rb') as fh:
        return tomllib.load(fh)


def analyses(system):
    return [k for k, v in system.items() if k not in SYSTEM_KEYS and isinstance(v, dict)]


def toml_value(v):
    if isinstance(v, bool):
        return 'true' if v else 'false'
    if isinstance(v, (int, float)):
        return repr(v)
    if isinstance(v, str):
        return json.dumps(v)        # a JSON string is a TOML basic string
    if isinstance(v, list) and not any(isinstance(x, dict) for x in v):
        return '[%s]' % ', '.join(toml_value(x) for x in v)
    raise BuildError('cannot write %r to TOML' % (v,))


def toml_dump(table, path=()):
    """TOML text of table (scalars, arrays, tables and arrays of tables)."""
    out = []
    subs = []
    for k, v in table.items():
        if isinstance(v, dict) or (isinstance(v, list) and v and all(isinstance(x, dict) for x in v)):
            subs.append((k, v))
        else:
            out.append('%s = %s' % (json.dumps(k), toml_value(v)))
    for k, v in subs:
        name = '.'.join(json.dumps(p) for p in path + (k,))
        for t in (v if isinstance(v, list) else [v]):
            out.append('')
            out.append(('[[%s]]' if isinstance(v, list) else '[%s]') % name)
            out.append(toml_dump(t, path + (k,)))
    return '\n'.join(out)


def write_if_changed(path, text):
    try:
        with open(path, encoding='utf-8') as fh:
            if fh.read() == text:
                return
    except FileNotFoundError:
        pass
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as fh:
        fh.write(text)


def main(argv):
    if argv[:1] == ['--list']:
        if len(argv) != 2:
            raise BuildError('usage: tee-build.py --list CASE')
        case_dir = os.path.abspath(argv[1])
        print(' '.join(analyses(load(os.path.join(case_dir, os.path.basename(case_dir) + '.toml')))))
        return 0
    ap = argparse.ArgumentParser(description='Build an analysis of a case study.')
    ap.add_argument('case', help='the case-study directory CASE (with CASE/CASE.toml)')
    ap.add_argument('analysis', help='the analysis ANALYSIS (the table [ANALYSIS] of CASE/CASE.toml)')
    ap.add_argument('--spec', help='a spec checkout to use instead of the [spec] revision')
    args = ap.parse_args(argv)

    case_dir = os.path.normpath(os.path.join(os.getcwd(), args.case))
    case = os.path.basename(case_dir)
    manifest = os.path.join(case_dir, case + '.toml')
    system = load(manifest)
    if args.analysis not in analyses(system):
        raise BuildError('%s: no analysis [%s]; the analyses are: %s'
                         % (manifest, args.analysis, ', '.join(analyses(system)) or 'none'))
    analysis = system[args.analysis]
    mode = analysis.get('mode', 'plain')
    if mode not in MODES:
        raise BuildError('%s: [%s] mode must be one of %s' % (manifest, args.analysis, ', '.join(MODES)))
    invisible = 'invisible' in analysis

    spec = system.get('spec', {})
    if args.spec:
        spec_dir, desc = os.path.abspath(args.spec), 'checkout %s' % args.spec
    else:
        if 'repo' not in spec or 'rev' not in spec:
            raise BuildError('%s: [spec] needs repo and rev' % manifest)
        spec_dir, commit = fetch_spec(spec['repo'], spec['rev'])
        desc = '%s %s (%s)' % (spec['repo'], commit, spec['rev'])
    features = spec_features(spec_dir, spec.get('features', {}))

    build = '%s-%s' % (case, args.analysis)
    rel = lambda p: os.path.relpath(p, ROOT)
    # the tables of the analysis, for the transforms (rewritten only when they change, so that an
    # unchanged analysis does not rebuild)
    analysis_toml = os.path.join(ROOT, 'build', build, args.analysis + '.toml')
    write_if_changed(analysis_toml,
                     '# Generated by tools/build/tee-build.py from [%s] of %s.\n%s\n'
                     % (args.analysis, rel(manifest),
                        toml_dump({k: v for k, v in analysis.items() if k != 'mode'})))
    make = ['make', '--no-print-directory', '-C', ROOT, '-f', 'tools/build/transform.mk', 'NAME=' + build, 'SPEC=' + rel(spec_dir), 'WITHOUT=']
    make += ['%s=%d' % kv for kv in sorted(features.items())]
    make += ['INVISIBLE=%d' % invisible,
             'DMC=%d' % (mode != 'plain'), 'M2L=%d' % (mode == 'm2l'),
             'DROP_ATTR=' + (rel(analysis_toml) if 'drop-class-attribute' in analysis else ''),
             'GHOST=' + (rel(analysis_toml) if 'ghost' in analysis else ''),
             'INVISIBLE_G=' + (rel(analysis_toml) if invisible else ''),
             'src']
    # the settings of a calling make (e.g. the Makefile of the case study) must not reach this one
    env = {k: v for k, v in os.environ.items() if k not in ('MAKEFLAGS', 'MFLAGS', 'MAKELEVEL', 'MAKEOVERRIDES')}
    if subprocess.run(make, env=env).returncode:
        return 1

    out = os.path.join(case_dir, 'models', args.analysis)
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(out)
    shutil.copytree(os.path.join(ROOT, 'build', build, 'src'), os.path.join(out, 'src'))
    shutil.copytree(os.path.join(case_dir, 'core'), os.path.join(out, 'core'))
    tas = []
    try:
        for section in ('ta', 'ra'):
            for key, table in system.get(section, {}).items():
                name = table.get('output', key + '.maude')
                preprocess.translate(manifest, key, os.path.join(out, section, name), section)
                print('tee-build: %s.%s -> %s' % (section, key, os.path.relpath(os.path.join(out, section, name))))
                tas.append(section + '/' + os.path.splitext(name)[0])
    except preprocess.TransError as ex:
        raise BuildError('preprocess: %s' % ex)
    with open(os.path.join(out, 'model.maude'), 'w', encoding='utf-8') as fh:
        fh.write('--- Generated by tools/build/tee-build.py from %s, analysis [%s].\n'
                 '--- spec: %s, mode %s%s, %s\n'
                 '--- The spec, the model files written by hand (core/) and the preprocessed TAs and RAs.\n'
                 'load src/main\nload core/main\n%s'
                 % (rel(manifest), args.analysis, desc, mode,
                    ', invisible-transition reduction' if invisible else '',
                    ' '.join('%s=%d' % kv for kv in sorted(features.items())),
                    ''.join('load %s\n' % t for t in tas)))
    with open(os.path.join(out, 'main.maude'), 'w', encoding='utf-8') as fh:
        fh.write('--- Generated by tools/build/tee-build.py: the model, then the entry module of the analyses.\n'
                 'load model\nload core/cmd/main\n')
    print('tee-build: %s' % os.path.relpath(os.path.join(out, 'main.maude')))
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv[1:]))
    except BuildError as ex:
        sys.exit('tee-build: error: %s' % ex)
