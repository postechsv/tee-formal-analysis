#!/usr/bin/env python3
"""tee-build: build an analysis of a case study.

Usage
    python3 tools/build/tee-build.py CASE ANALYSIS [--spec DIR]
    (make ANALYSIS in CASE/, with the Makefile of the case study)
    python3 tools/build/tee-build.py --list CASE      (the analyses of CASE)

An analysis ANALYSIS of a case study CASE is the file CASE/ANALYSIS.toml (a TOML file of CASE with a
[spec] table), standalone: it says what the analyzed system is,
    [spec]            the specification: repo (a git URL) and rev (a commit, branch or tag), or
                      checkout (a tee-formal-spec checkout, relative to CASE/; --spec overrides
                      both), without = [MODULE, ...] (modules the spec build leaves out, make
                      WITHOUT=, each a pr line of its src/main.maude), and
                      [spec.features] (FEATURE = 0 or 1): overrides of the spec's feature selection,
                      passed to the spec build as its build configuration file (make CONFIG=FILE,
                      build/CASE-ANALYSIS/spec-config.toml: one top-level "F = V" line per feature,
                      the format of the spec's features.toml, which its Makefile includes).  The
                      spec rejects a name that is not one of its features; a feature not listed
                      has the default of the spec (its features.mk)
    [ta.KEY]          a trusted application preprocessed from its C source (tools/lang/preprocess.py)
    [ra.KEY]          a rich application (the client of the TAs) preprocessed the same way
and how it is analyzed:
    mode              plain, dmc (DM-Check build) or m2l (maude2lean build); default plain
    output            the directory of the built model, relative to CASE/ and inside it; default
                      models/ANALYSIS
    m2l-eq            mode m2l: false leaves out gen-dmc's _.=._ (make M2L_EQ=0); default true
    check             mode dmc or m2l: true runs the checks of gen-dmc or gen-maude2lean on a fresh
                      build (make check-dmc, check-m2l); default false
    ghost-modules     ghost modules (.maude files, relative to CASE/) composed with the spec rules
                      after the [ghost] tables (make GHOST=x.maude)
    drop-rules        labels of spec rules that the analysis leaves out (tools/build/drop-rules.py),
                      for an assumption of the analysis that differs from the spec
    [drop-class-attribute]  class attributes dropped from rule left-hand sides
                      (tools/build/drop-class-attribute.py)
    [ghost]           ghost attributes of spec objects (tools/build/ghost.py)
    [invisible]       the invisible-transition reduction: the rules turned into equations
                      (tools/build/gen-invisible.py); without it, there is no reduction
    [dmc]             the directives of the DM-Check transform (tools/dmc/gen-dmc.py), needed by
                      mode dmc and m2l: the tables of the directives format (gen-dmc's docstring)
The paths in ANALYSIS.toml are relative to it.  The transforms read the tables of the analysis from
build/CASE-ANALYSIS/ANALYSIS.toml, which is written from them.

The spec revision is fetched into the cache build/spec/ (build/spec/repos/ holds a bare clone per
repo, build/spec/<commit>/ the tree of a commit), or --spec DIR names a checkout to use instead.  It
is built and transformed by tools/build/transform.mk into build/CASE-ANALYSIS/, and the output
directory is then written from scratch with the final model, which loads on its own:
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

import importlib.util  # noqa: E402
_pre = importlib.util.spec_from_file_location(
    'lang_preprocess', os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'lang-preprocess.py'))
preprocess = importlib.util.module_from_spec(_pre)
_pre.loader.exec_module(preprocess)

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
SPEC_CACHE = os.path.join(ROOT, 'build', 'spec')
MODES = ('plain', 'dmc', 'm2l')
SYSTEM_KEYS = ('spec', 'ta', 'ra')
ANALYSIS_KEYS = ('mode', 'output', 'm2l-eq', 'check', 'ghost-modules',
                 'drop-rules', 'drop-class-attribute', 'ghost', 'invisible', 'dmc')
SPEC_KEYS = ('repo', 'rev', 'checkout', 'features', 'without')
TRANSFORM_KEYS = ('drop-rules', 'drop-class-attribute', 'ghost', 'invisible', 'dmc')


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


def feature_names(spec_dir):
    """The features of the spec (FEATURES of its features.mk).  The spec must take a build
    configuration file (make CONFIG=FILE of "F = V" lines, read by its Makefile; features.toml)."""
    if not os.path.exists(os.path.join(spec_dir, 'features.toml')):
        raise BuildError('%s: the spec revision has no build configuration file (make CONFIG=FILE, '
                         'features.toml): use a later revision' % spec_dir)
    with open(os.path.join(spec_dir, 'features.mk'), encoding='utf-8') as fh:
        m = re.search(r'^FEATURES\s*:=\s*(.*)$', fh.read(), re.MULTILINE)
    if not m:
        raise BuildError('%s/features.mk: no FEATURES list' % spec_dir)
    return m.group(1).split()


def spec_config_text(features):
    """The build configuration file of the spec for [spec.features]: one "F = V" line each, V 0
    or 1 (the spec's Makefile includes the file, so no tables, quotes or other values)."""
    lines = []
    for name, value in features.items():
        if not re.fullmatch(r'[A-Za-z0-9_]+', name):
            raise BuildError('[spec.features]: %r is not a feature name' % name)
        if isinstance(value, bool) or value not in (0, 1):
            raise BuildError('[spec.features]: %s = %r: a feature is 0 or 1' % (name, value))
        lines.append('%s = %d\n' % (name, value))
    return ''.join(lines)


def built_features(config_mk, names):
    """FEATURE=VALUE of a spec build, from the settings it cached (build/NAME/config.mk)."""
    with open(config_mk, encoding='utf-8') as fh:
        values = dict(re.findall(r'^(\w+)\s*:=\s*(\S*)\s*$', fh.read(), re.MULTILINE))
    return {f: values.get(f, '?') for f in names}


def load(path):
    with open(path, 'rb') as fh:
        return tomllib.load(fh)


def analyses(case_dir):
    """The analyses of a case study: its TOML files with a [spec] table."""
    out = []
    for f in sorted(os.listdir(case_dir)):
        if f.endswith('.toml') and os.path.isfile(os.path.join(case_dir, f)) and 'spec' in load(os.path.join(case_dir, f)):
            out.append(f[:-len('.toml')])
    return out


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
        print(' '.join(analyses(case_dir)))
        return 0
    ap = argparse.ArgumentParser(description='Build an analysis of a case study.')
    ap.add_argument('case', help='the case-study directory CASE')
    ap.add_argument('analysis', help='the analysis ANALYSIS (the file CASE/ANALYSIS.toml)')
    ap.add_argument('--spec', help='a spec checkout to use instead of the [spec] revision')
    args = ap.parse_args(argv)

    case_dir = os.path.normpath(os.path.join(os.getcwd(), args.case))
    case = os.path.basename(case_dir)
    manifest = os.path.join(case_dir, args.analysis + '.toml')
    if args.analysis not in analyses(case_dir):
        raise BuildError('%s: no analysis %s (a file %s.toml with a [spec] table); the analyses are: %s'
                         % (case_dir, args.analysis, args.analysis, ', '.join(analyses(case_dir)) or 'none'))
    system = load(manifest)
    unknown = [k for k in system if k not in SYSTEM_KEYS + ANALYSIS_KEYS]
    if unknown:
        raise BuildError('%s: unknown key(s) %s (expected %s)'
                         % (manifest, ', '.join(unknown), ', '.join(SYSTEM_KEYS + ANALYSIS_KEYS)))
    analysis = {k: system[k] for k in TRANSFORM_KEYS if k in system}
    mode = system.get('mode', 'plain')
    if mode not in MODES:
        raise BuildError('%s: mode must be one of %s' % (manifest, ', '.join(MODES)))
    if mode != 'plain' and 'dmc' not in analysis:
        raise BuildError('%s: mode %s needs the directives of the DM-Check transform, [dmc]' % (manifest, mode))
    # the output directory is rewritten from scratch: it must be a directory of its own in CASE/
    output = os.path.normpath(system.get('output', os.path.join('models', args.analysis)))
    if (os.path.isabs(output) or output in ('.', 'core') or output.split(os.sep)[0] in ('..', 'core')
            or output.endswith('.toml')):
        raise BuildError('%s: output %s must be a directory inside %s, other than core/' % (manifest, output, case_dir))
    invisible = 'invisible' in analysis

    spec = system.get('spec', {})
    bad = [k for k in spec if k not in SPEC_KEYS]
    if bad:
        raise BuildError('%s: [spec] unknown key(s) %s (expected %s)' % (manifest, ', '.join(bad), ', '.join(SPEC_KEYS)))
    without = spec.get('without', [])
    if not (isinstance(without, list) and all(isinstance(m, str) and re.fullmatch(r'[\w\-]+', m) for m in without)):
        raise BuildError('%s: [spec] without must be a list of module names' % manifest)
    m2l_eq = system.get('m2l-eq', True)
    check = system.get('check', False)
    for key, val in (('m2l-eq', m2l_eq), ('check', check)):
        if not isinstance(val, bool):
            raise BuildError('%s: %s must be true or false' % (manifest, key))
    if check and mode == 'plain':
        raise BuildError('%s: check runs the checks of a dmc or m2l build; mode is plain' % manifest)
    ghost_modules = []
    for p in system.get('ghost-modules', []):
        path = os.path.normpath(os.path.join(case_dir, p))
        if not (p.endswith('.maude') and os.path.isfile(path)):
            raise BuildError('%s: ghost-modules: %s is not a .maude file' % (manifest, p))
        ghost_modules.append(path)
    if args.spec:
        spec_dir, desc = os.path.abspath(args.spec), 'checkout %s' % args.spec
    elif 'checkout' in spec:
        spec_dir = os.path.normpath(os.path.join(case_dir, spec['checkout']))
        if not os.path.isfile(os.path.join(spec_dir, 'Makefile')):
            raise BuildError('%s: [spec] checkout %s is not a tee-formal-spec checkout' % (manifest, spec['checkout']))
        desc = 'checkout %s' % spec['checkout']
    else:
        if 'repo' not in spec or 'rev' not in spec:
            raise BuildError('%s: [spec] needs repo and rev, or checkout' % manifest)
        spec_dir, commit = fetch_spec(spec['repo'], spec['rev'])
        desc = '%s %s (%s)' % (spec['repo'], commit, spec['rev'])
    names = feature_names(spec_dir)

    build = '%s-%s' % (case, args.analysis)
    rel = lambda p: os.path.relpath(p, ROOT)
    # the tables of the analysis, for the transforms (rewritten only when they change, so that an
    # unchanged analysis does not rebuild)
    analysis_toml = os.path.join(ROOT, 'build', build, args.analysis + '.toml')
    write_if_changed(analysis_toml,
                     '# Generated by tools/build/tee-build.py from %s.\n%s\n'
                     % (rel(manifest), toml_dump(analysis)))
    # [spec.features], the build configuration file of the spec build: top-level "F = V" lines,
    # which the spec's Makefile includes (the spec checks the names)
    spec_config_toml = os.path.join(ROOT, 'build', build, 'spec-config.toml')
    write_if_changed(spec_config_toml,
                     '# Generated by tools/build/tee-build.py from [spec.features] of %s.\n%s'
                     % (rel(manifest), spec_config_text(spec.get('features', {}))))
    make = ['make', '--no-print-directory', '-C', ROOT, '-f', 'tools/build/transform.mk', 'NAME=' + build, 'SPEC=' + rel(spec_dir),
            'WITHOUT=' + ' '.join(without), 'CONFIG=' + spec_config_toml]
    ghosts = ([rel(analysis_toml)] if 'ghost' in analysis else []) + [rel(p) for p in ghost_modules]
    make += ['DMC=%d' % (mode != 'plain'), 'M2L=%d' % (mode == 'm2l'), 'M2L_EQ=%d' % m2l_eq,
             'DMC_DIRECTIVES=' + (rel(analysis_toml) if 'dmc' in analysis else ''),
             'DROP_RULES=' + (rel(analysis_toml) if 'drop-rules' in analysis else ''),
             'DROP_ATTR=' + (rel(analysis_toml) if 'drop-class-attribute' in analysis else ''),
             'GHOST=' + ' '.join(ghosts),
             'INVISIBLE_G=' + (rel(analysis_toml) if invisible else '')]
    # check: the checks of gen-dmc (DMC_CHECK) or of gen-maude2lean (M2L_CHECK) on a fresh build, as
    # make check-dmc / check-m2l of transform.mk do
    if check:
        make += ['-B', 'DMC_CHECK=1' if mode == 'dmc' else 'M2L_CHECK=1']
    make += ['src']
    # the settings of a calling make (e.g. the Makefile of the case study) must not reach this one
    # nor the environment values of the features: a feature is set by the spec or by [spec.features]
    env = {k: v for k, v in os.environ.items()
           if k not in ('MAKEFLAGS', 'MFLAGS', 'MAKELEVEL', 'MAKEOVERRIDES') and k not in names}
    # The spec build caches its feature settings (build/NAME/config.mk) and reads them before
    # features.mk, so a feature that [spec.features] no longer sets would keep its old value:
    # without the cache it takes the default of the spec.  The build still depends on the
    # settings (config.want), so an unchanged selection does not rebuild.
    spec_config = os.path.join(spec_dir, 'build', build, 'config.mk')
    if os.path.exists(spec_config):
        os.remove(spec_config)
    if subprocess.run(make, env=env).returncode:
        return 1
    features = built_features(spec_config, names)

    out = os.path.join(case_dir, output)
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(out)
    shutil.copytree(os.path.join(ROOT, 'build', build, 'src'), os.path.join(out, 'src'))
    # the language files of a spec that loads them from next to src/ (load ../lang/c/semantics)
    if os.path.isdir(os.path.join(ROOT, 'build', build, 'lang')):
        shutil.copytree(os.path.join(ROOT, 'build', build, 'lang'), os.path.join(out, 'lang'))
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
        fh.write('--- Generated by tools/build/tee-build.py from %s, analysis %s.\n'
                 '--- spec: %s, mode %s%s, %s\n'
                 '--- The spec, the model files written by hand (core/) and the preprocessed TAs and RAs.\n'
                 'load src/main\nload core/main\n%s'
                 % (rel(manifest), args.analysis, desc, mode,
                    ', invisible-transition reduction' if invisible else '',
                    ' '.join('%s=%s' % kv for kv in sorted(features.items())),
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
