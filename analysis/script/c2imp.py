#!/usr/bin/env python3
"""Translate an annotated C TA program into the C-like TEE-IMP syntax of tee-formal-spec.

Usage (defaults reproduce analysis/mqttz/broker-ta.maude):

    python3 c2imp.py [--source C] [--template MAUDE] [--main TXT] [--target OUT]

The translated program, followed by the contents of --main, replaces the line
`---@translated` of --template.  `--target -` writes to stdout.

What is translated
------------------
Only the regions `//@process_struct` ... `//@endprocess_struct` and every
function definition preceded by `//@func_start`; everything else is dropped.
Inside them, comments, blank-only-after-stripping lines, and logging / timing
calls (printf, EMSG, TEE_Free, TEE_GetSystemTime, ...) are dropped.  Each
remaining line must hold one complete statement, declaration, label, or brace.

The translation itself is mechanical:
  * identifiers         snake_case -> camelCase, struct names -> PascalCase
  * `a->b`, `a.b`       -> `a . b`;  `x = e`  -> `x := e`;  `&x`, `*x`, casts dropped
  * literals            `n` -> `# n`;  NULL -> `# noData`;  TA_FOO -> `# TA-FOO`
  * TEE constants       via CONSTANTS;  `TEE_DATA_FLAG_A | ...` -> `# (a, ...)`
  * TEE API calls       via API (IMP name + argument order of the model)
  * TEE_Malloc(...)     -> `# noData`
  * declarations        C type -> IMP type via C_TYPES (overridable, see //@type)

Annotations (each `//@` directive is on its own line)
-----------------------------------------------------
Region / scope:
  //@ignore ... //@endignore      drop the enclosed lines
  //@process_struct ... //@endprocess_struct
  //@func_start                   translate the next function definition
Function level (between //@func_start and the function header):
  //@param NAME IMP-TYPE          IMP type of parameter NAME (e.g. `TEE-Buffer &`)
  //@params IMP-PARAM-LIST        replace the whole parameter list
  //@alias A B                    A is a local alias of B: drop the declaration
                                  of A and the assignment `A = ...;`, rename A to B
Statement level (apply to the next translated line):
  //@type IMP-TYPE                IMP type of the declared variable
  //@expr IMP-EXPR                right-hand side of the assignment
  //@assign X                     the call statement assigns its result to X
  //@drop TEXT                    remove the literal C text TEXT first
  //@subst ID => IMP-TEXT         replace the IMP identifier ID afterwards
Insertion:
  //@insert IMP-TEXT              emit IMP-TEXT as a line here
Any other `//@` directive is an error.
"""

import argparse
import os
import re
import sys

# --------------------------------------------------------------------------
# Tables
# --------------------------------------------------------------------------

# C type -> IMP type for declarations, parameters, and return types.
# Struct types found in //@process_struct are added at run time.
C_TYPES = {
    'TEE_Result':          'TEE-Result',
    'TEE_Attribute':       'TEE-Attributes',
    'TEE_ObjectHandle':    'TEE-Handle',
    'TEE_OperationHandle': 'TEE-Handle',
    'TEE_ObjectInfo':      'struct TeeObjectInfo',
    'char':                'TEE-Buffer',      # only as `char *`
    'uint32_t':            'int',
    'size_t':              'int',
    'int':                 'int',
    'void':                'void',
}

# Struct name map (C -> IMP); others are PascalCased.
STRUCT_NAMES = {
    'TEE_ObjectInfo': 'TeeObjectInfo',
}

# TEE constants -> IMP data constants (emitted as `# value`).
CONSTANTS = {
    'TEE_SUCCESS':               'success',
    'TEE_HANDLE_NULL':           'null',
    'TEE_ERROR_GENERIC':         'errorGeneric',
    'TEE_ERROR_BAD_PARAMETERS':  'errorBadParameters',
    'TEE_ERROR_BAD_STATE':       'errorBadState',
    'TEE_ERROR_OUT_OF_MEMORY':   'errorOutOfMemory',
    'TEE_ERROR_NOT_SUPPORTED':   'errorNotSupported',
    'TEE_ERROR_ITEM_NOT_FOUND':  'errorItemNotFound',
    'TEE_ERROR_SHORT_BUFFER':    'errorShortBuffer',
    'TEE_ALG_AES_CBC_NOPAD':     'algAesCbcNopad',
    'TEE_MODE_ENCRYPT':          'modeEncrypt',
    'TEE_MODE_DECRYPT':          'modeDecrypt',
    'TEE_TYPE_AES':              'typeAes',
    'TEE_ATTR_SECRET_VALUE':     'secretValue',
    'TEE_STORAGE_PRIVATE':       'storagePrivate',
    'NULL':                      'noData',
}

# TEE_DATA_FLAG_* -> IMP flag names, used inside `# (f1, f2, ...)`.
DATA_FLAGS = {
    'TEE_DATA_FLAG_ACCESS_READ':        'accessRead',
    'TEE_DATA_FLAG_ACCESS_WRITE':       'accessWrite',
    'TEE_DATA_FLAG_ACCESS_WRITE_META':  'accessWriteMeta',
    'TEE_DATA_FLAG_SHARE_READ':         'shareRead',
    'TEE_DATA_FLAG_SHARE_WRITE':        'shareWrite',
    'TEE_DATA_FLAG_OVERWRITE':          'overwrite',
}

# TEE API -> (IMP name, C arity, IMP arguments).  An IMP argument is the index
# of a C argument, or (index, wrapper) where `# v` becomes `# wrapper(v)`.
# C arities are those of the preprocessed source (e.g. buffer sizes of
# TEE_CipherUpdate are already removed there).
API = {
    'TEE_AllocateOperation':        ('allocOperation', 4, [1, 2, 3, 0]),
    'TEE_FreeOperation':            ('freeOperation', 1, [0]),
    'TEE_ResetOperation':           ('resetOperation', 1, [0]),
    'TEE_SetOperationKey':          ('setOperationKey', 2, [0, 1]),
    'TEE_CipherInit':               ('cipherInit', 3, [0, 1]),
    'TEE_CipherUpdate':             ('cipherUpdate', 3, [0, 1, 2]),
    'TEE_AllocateTransientObject':  ('allocateTransientObject', 3, [0, 1, 2]),
    'TEE_FreeTransientObject':      ('freeTransientObject', 1, [0]),
    'TEE_ResetTransientObject':     ('resetTransientObject', 1, [0]),
    'TEE_PopulateTransientObject':  ('populateTransientObject', 3, [0, 1]),
    'TEE_InitRefAttribute':         ('initRefAttribute', 4, [1, 2, 0]),
    'TEE_OpenPersistentObject':     ('openPersistentObject', 5, [0, 1, 3, 4]),
    'TEE_CreatePersistentObject':   ('createPersistent', 8, [0, 1, 3, 4, 5, (6, 'dataSize'), 7]),
    'TEE_GetObjectInfo1':           ('getObjectInfo1', 2, [0, 1]),
    'TEE_ReadObjectData':           ('readObjData', 4, [0, 2, 1]),
    'TEE_WriteObjectData':          ('writeObjectData', 3, [0, 1]),
    'TEE_CloseObject':              ('closeObject', 1, [0]),
    'TEE_CloseAndDeletePersistentObject1': ('closeAndDeletePersistentObject1', 1, [0]),
}

# Statements starting with these calls are dropped (logging, timing, free).
DROPPED_CALLS = {'printf', 'snprintf', 'sprintf', 'EMSG', 'DMSG', 'IMSG',
                 'TEE_Free', 'TEE_GetSystemTime', 'TEE_TIME_SUB'}

KEYWORDS = {'if', 'else', 'return', 'goto', 'while'}
C_TYPE_WORDS = set(C_TYPES) | {'const', 'struct', 'static', 'unsigned'}

INDENT_BASE = 4      # indentation of top-level program items in the template
LABEL_INDENT = 2     # extra indentation of statements after a label


class TranslationError(Exception):
    pass


# --------------------------------------------------------------------------
# Names
# --------------------------------------------------------------------------

def camel(name):
    parts = name.split('_')
    return parts[0] + ''.join(p[:1].upper() + p[1:] for p in parts[1:])


def pascal(name):
    return ''.join(p[:1].upper() + p[1:].lower() if p.isupper() else p[:1].upper() + p[1:]
                   for p in name.split('_'))


def struct_name(c_name):
    return STRUCT_NAMES.get(c_name) or pascal(c_name)


# --------------------------------------------------------------------------
# Tokens
# --------------------------------------------------------------------------

TOKEN_RE = re.compile(r'\s*(->|==|!=|<=|>=|&&|\|\||[A-Za-z_]\w*|\d+|"(?:\\.|[^"])*"|\S)')


def tokenize(text):
    toks, pos = [], 0
    text = text.rstrip()
    while pos < len(text):
        m = TOKEN_RE.match(text, pos)
        if not m:
            break
        toks.append(m.group(1))
        pos = m.end()
    return toks


def is_ident(t):
    return re.fullmatch(r'[A-Za-z_]\w*', t) is not None


def render(toks):
    """Print IMP tokens: `f(a, b) ;`, `x . y`, `! (c)`, `# (a, b)`, `if (c) {`."""
    out = ''
    prev = None
    for t in toks:
        if prev is None:
            out = t
        elif t in (')', ',') or prev == '(' or \
                (t == '(' and is_ident(prev) and prev not in KEYWORDS):
            out += t
        else:
            out += ' ' + t
        prev = t
    return out


def matching_paren(toks, i):
    depth = 0
    for j in range(i, len(toks)):
        if toks[j] == '(':
            depth += 1
        elif toks[j] == ')':
            depth -= 1
            if depth == 0:
                return j
    raise TranslationError('unbalanced parentheses: ' + ' '.join(toks))


def split_args(toks):
    args, cur, depth = [], [], 0
    for t in toks:
        if t == ',' and depth == 0:
            args.append(cur)
            cur = []
            continue
        if t == '(':
            depth += 1
        elif t == ')':
            depth -= 1
        cur.append(t)
    if cur or args:
        args.append(cur)
    return args


# --------------------------------------------------------------------------
# Expressions
# --------------------------------------------------------------------------

class Translator:
    def __init__(self):
        self.types = dict(C_TYPES)
        self.renames = {}

    def is_cast(self, toks, i):
        """`( [const] T [*]* )` with T a C type at position i."""
        j = i + 1
        if j < len(toks) and toks[j] == 'const':
            j += 1
        if j >= len(toks) or toks[j] not in self.types:
            return None
        j += 1
        while j < len(toks) and toks[j] == '*':
            j += 1
        return j if j < len(toks) and toks[j] == ')' else None

    def expr(self, toks):
        """Translate a C token list (expression or statement) to IMP tokens."""
        out, i = [], 0
        while i < len(toks):
            t = toks[i]
            prev = out[-1] if out else None
            unary_pos = prev is None or prev in ('(', ',', '=', ':=', '!', '==', 'return')
            if t == '(':
                end = self.is_cast(toks, i)
                if end is not None:              # cast: drop
                    i = end + 1
                    continue
                out.append(t)
            elif t in ('&', '*') and unary_pos:  # address-of / dereference: drop
                pass
            elif t == '->' or t == '.':
                out.append('.')
            elif t == '=':
                out.append(':=')
            elif t in ('!=', '<', '>', '<=', '>=', '&&', '||'):
                raise TranslationError("operator '%s' is not supported; rewrite it in the "
                                       "preprocessed source" % t)
            elif t.isdigit():
                out += ['#', t]
            elif t in DATA_FLAGS:                # TEE_DATA_FLAG_A | TEE_DATA_FLAG_B ...
                flags = [DATA_FLAGS[t]]
                i += 1
                while i + 1 < len(toks) and toks[i] == '|' and toks[i + 1] in DATA_FLAGS:
                    flags.append(DATA_FLAGS[toks[i + 1]])
                    i += 2
                out += ['#', '(']
                for k, f in enumerate(flags):
                    out += ([','] if k else []) + [f]
                out.append(')')
                continue
            elif is_ident(t) and i + 1 < len(toks) and toks[i + 1] == '(' and t not in KEYWORDS:
                end = matching_paren(toks, i + 1)
                out += self.call(t, toks[i + 2:end])
                i = end + 1
                continue
            elif t in CONSTANTS:
                out += ['#', CONSTANTS[t]]
            elif t.startswith('TEE_'):
                raise TranslationError("unknown TEE constant '%s' (add it to CONSTANTS)" % t)
            elif re.fullmatch(r'TA_[A-Z0-9_]+', t):
                out += ['#', t.replace('_', '-')]
            elif is_ident(t) and t not in KEYWORDS:
                out.append(camel(self.renames.get(t, t)))
            else:
                out.append(t)
            i += 1
        return out

    def call(self, name, arg_toks):
        if name == 'TEE_Malloc':
            return ['#', 'noData']
        args = [self.expr(a) for a in split_args(arg_toks)]
        if name in API:
            imp, arity, order = API[name]
            if len(args) != arity:
                raise TranslationError('%s: expected %d arguments, got %d'
                                       % (name, arity, len(args)))
            new_args = []
            for spec in order:
                if isinstance(spec, tuple):
                    idx, wrapper = spec
                    a = args[idx]
                    if a[:1] != ['#']:
                        raise TranslationError('%s: argument %d must be a constant' % (name, idx))
                    new_args.append(['#', wrapper, '('] + a[1:] + [')'])
                else:
                    new_args.append(args[spec])
            args, name = new_args, imp
        elif name.startswith('TEE_'):
            raise TranslationError("unknown TEE API '%s' (add it to API)" % name)
        else:
            name = camel(name)
        out = [name, '(']
        for k, a in enumerate(args):
            out += ([','] if k else []) + a
        return out + [')']

    # ----------------------------------------------------------------------
    # Declarations and signatures
    # ----------------------------------------------------------------------

    def decl(self, toks):
        """Match `[const] [struct] T [*]* name [ [...] ] ;` -> (C type, name) or None."""
        i = 0
        while i < len(toks) and toks[i] in ('const', 'static', 'struct', 'unsigned'):
            i += 1
        if i >= len(toks) or toks[i] not in self.types:
            return None
        ctype = toks[i]
        i += 1
        while i < len(toks) and toks[i] == '*':
            i += 1
        if i >= len(toks) or not is_ident(toks[i]):
            return None
        name = toks[i]
        i += 1
        if i < len(toks) and toks[i] == '[':
            while i < len(toks) and toks[i] != ']':
                i += 1
            i += 1
        if toks[i:] != [';']:
            return None
        return ctype, name

    def imp_type(self, ctype, override=None):
        if override:
            return override
        if ctype not in self.types or ctype == 'void':
            raise TranslationError("no IMP type for C type '%s' (use //@type or //@param)" % ctype)
        return self.types[ctype]

    def header(self, toks, func_dirs):
        """`[static] RET name ( params )` -> IMP header string."""
        toks = [t for t in toks if t not in ('static', 'const')]
        if '(' not in toks or toks[-1] != ')':
            raise TranslationError('function header must be on one line: ' + ' '.join(toks))
        lp = toks.index('(')
        ret, name = toks[0], toks[lp - 1]
        ret_imp = self.types.get(ret)
        if ret_imp is None:
            raise TranslationError("no IMP type for return type '%s'" % ret)
        if 'params' in func_dirs:
            params = func_dirs['params']
        else:
            parts = []
            for p in split_args(toks[lp + 1:-1]):
                p = [t for t in p if t != 'const']
                pname = p[-1]
                override = func_dirs['param'].pop(pname, None)
                parts.append('%s %s' % (self.imp_type(p[0], override), camel(pname)))
            if func_dirs['param']:
                raise TranslationError('//@param for unknown parameter(s): %s'
                                       % ', '.join(func_dirs['param']))
            params = ', '.join(parts)
        return '%s %s (%s)' % (ret_imp, camel(name), params)


# --------------------------------------------------------------------------
# Source preprocessing
# --------------------------------------------------------------------------

DIRECTIVE_RE = re.compile(r'^\s*//@(\w+)\s?(.*)$')


def remove_ignored(lines):
    out, ignoring = [], False
    for n, line in lines:
        m = DIRECTIVE_RE.match(line)
        if m and m.group(1) == 'ignore':
            if ignoring:
                raise TranslationError('line %d: nested //@ignore' % n)
            ignoring = True
        elif m and m.group(1) == 'endignore':
            if not ignoring:
                raise TranslationError('line %d: //@endignore without //@ignore' % n)
            ignoring = False
        elif not ignoring:
            out.append((n, line))
    if ignoring:
        raise TranslationError('unterminated //@ignore')
    return out


def remove_comments(lines):
    """Remove /* */ and // comments; keep //@ directive lines; mark comment-only lines."""
    out, in_block = [], False
    for n, line in lines:
        if not in_block and DIRECTIVE_RE.match(line):
            out.append((n, line.rstrip('\n'), False))
            continue
        res, i, had_comment = '', 0, False
        while i < len(line):
            if in_block:
                end = line.find('*/', i)
                had_comment = True
                if end < 0:
                    i = len(line)
                else:
                    in_block, i = False, end + 2
            elif line.startswith('/*', i):
                in_block, i, had_comment = True, i + 2, True
            elif line.startswith('//', i):
                had_comment = True
                break
            elif line[i] == '"':
                m = re.compile(r'"(?:\\.|[^"])*"').match(line, i)
                j = m.end() if m else len(line)
                res, i = res + line[i:j], j
            else:
                res, i = res + line[i], i + 1
        res = res.rstrip()
        # a line that only held a comment disappears; a truly blank line stays
        out.append((n, res, had_comment and not res.strip()))
    return out


def indent_of(line):
    expanded = line.expandtabs(4)
    return len(expanded) - len(expanded.lstrip())


# --------------------------------------------------------------------------
# Driver
# --------------------------------------------------------------------------

def translate_source(path):
    with open(path) as f:
        raw = list(enumerate(f.readlines(), 1))
    lines = remove_comments(remove_ignored(raw))

    tr = Translator()
    out = []
    mode = None            # None | 'struct' | 'func-pending' | 'func'
    depth = 0
    after_label = False
    func_dirs = None
    stmt_dirs = {}

    def emit(text, c_indent, extra=0):
        out.append(' ' * (INDENT_BASE + c_indent // 2 + extra) + text)

    def blank():
        if out and out[-1] != '':
            out.append('')

    def take(key, default=None):
        return stmt_dirs.pop(key, default)

    for n, line, comment_only in lines:
        try:
            m = DIRECTIVE_RE.match(line)
            if m:
                name, arg = m.group(1), m.group(2).strip()
                if name == 'process_struct':
                    mode = 'struct'
                    blank()
                elif name == 'endprocess_struct':
                    mode = None
                elif name == 'func_start':
                    mode = 'func-pending'
                    func_dirs = {'param': {}, 'alias': {}}
                elif name == 'param' and mode == 'func-pending':
                    pname, ptype = arg.split(None, 1)
                    func_dirs['param'][pname] = ptype
                elif name == 'params' and mode == 'func-pending':
                    func_dirs['params'] = arg
                elif name == 'alias' and mode == 'func-pending':
                    a, b = arg.split()
                    func_dirs['alias'][a] = b
                elif name in ('type', 'expr', 'assign') and mode in ('struct', 'func'):
                    stmt_dirs[name] = arg
                elif name == 'drop' and mode == 'func':
                    stmt_dirs.setdefault('drop', []).append(arg)
                elif name == 'subst' and mode == 'func':
                    a, b = [s.strip() for s in arg.split('=>', 1)]
                    stmt_dirs.setdefault('subst', []).append((a, b))
                elif name == 'insert' and mode == 'func':
                    emit(arg, indent_of(line), LABEL_INDENT if after_label else 0)
                else:
                    raise TranslationError("directive //@%s not allowed here" % name)
                continue

            if mode is None or comment_only:
                continue
            if not line.strip():
                if mode == 'func' and depth > 0:
                    blank()
                continue

            c_indent = indent_of(line)
            text = line.strip()
            for d in take('drop', []):
                if d not in text:
                    raise TranslationError("//@drop text '%s' not found" % d)
                text = text.replace(d, '')
            toks = tokenize(text)

            if mode == 'struct':
                if toks[:2] in (['typedef', 'struct'], ['struct']) or toks[:1] == ['typedef']:
                    cname = [t for t in toks if is_ident(t) and t not in ('typedef', 'struct')]
                    if not cname or toks[-1] != '{':
                        raise TranslationError('struct header must name the struct and open { on '
                                               'the same line')
                    tr.types[cname[0]] = 'struct ' + struct_name(cname[0])
                    emit('struct %s {' % struct_name(cname[0]), c_indent)
                elif toks[0] == '}':
                    emit('} ;', c_indent)
                    blank()
                else:
                    d = tr.decl(toks)
                    if d is None:
                        raise TranslationError('not a field declaration')
                    emit('%s %s ;' % (tr.imp_type(d[0], take('type')), camel(d[1])), c_indent)
                continue

            if mode == 'func-pending':      # function header
                blank()
                tr.renames = dict(func_dirs['alias'])
                emit(tr.header(toks, func_dirs), c_indent)
                if toks[-1] == '{':
                    depth = 1
                mode, after_label = 'func', False
                continue

            # ---- function body ----
            opens, closes = toks.count('{'), toks.count('}')
            if depth == 0:
                if toks != ['{']:
                    raise TranslationError("expected '{' after the function header")
                emit('{', c_indent)
                depth = 1
                continue

            if toks[0] in DROPPED_CALLS and len(toks) > 1 and toks[1] == '(':
                continue

            extra = LABEL_INDENT if after_label else 0
            if len(toks) == 2 and is_ident(toks[0]) and toks[1] == ':':     # label
                # labels sit at the body level, the statements after them one level deeper
                emit('%s :' % toks[0], 0, LABEL_INDENT)
                after_label = True
                continue

            d = tr.decl(toks)
            if d is not None:
                if d[1] in tr.renames:                 # declaration of an alias
                    continue
                emit('%s %s ;' % (tr.imp_type(d[0], take('type')), camel(d[1])), c_indent, extra)
            elif len(toks) >= 2 and toks[0] in tr.renames and toks[1] == '=':
                continue                               # alias assignment
            else:
                expr = take('expr')
                assign = take('assign')
                if assign is not None:
                    toks = [assign, '='] + toks
                if expr is not None:
                    if '=' not in toks or toks[-1] != ';':
                        raise TranslationError('//@expr needs an assignment `x = ...;`')
                    lhs = toks[:toks.index('=') + 1]
                    imp = render(tr.expr(lhs)) + ' ' + expr + ' ;'
                else:
                    imp = render(tr.expr(toks))
                for a, b in take('subst', []):
                    imp, k = re.subn(r'(?<![\w#])%s(?!\w)' % re.escape(a), lambda _m: b, imp)
                    if k == 0:
                        raise TranslationError("//@subst identifier '%s' not found" % a)
                emit(imp, c_indent, 0 if closes and not opens and depth - closes == 0 else extra)

            depth += opens - closes
            if depth == 0:                              # end of function
                mode, func_dirs, after_label = None, None, False
                tr.renames = {}
            if stmt_dirs:
                raise TranslationError('unused directive(s): %s' % ', '.join(stmt_dirs))
        except TranslationError as e:
            raise TranslationError('%s:%d: %s\n    %s' % (path, n, e, line.strip())) from None

    if mode is not None:
        raise TranslationError('%s: unterminated struct/function at end of file' % path)
    while out and out[-1] == '':
        out.pop()
    return out


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--source', default=os.path.join(here, 'mqttz', 'preprocessed-ta.c'))
    ap.add_argument('--template', default=os.path.join(here, 'mqttz', 'template.maude'))
    ap.add_argument('--main', default=os.path.join(here, 'mqttz', 'custom_main.txt'))
    ap.add_argument('--target', default=os.path.join(here, '..', 'mqttz', 'broker-ta.maude'))
    args = ap.parse_args()

    try:
        program = translate_source(args.source)
    except TranslationError as e:
        sys.exit('c2imp: ' + str(e))

    with open(args.main) as f:
        program += [''] + f.read().rstrip('\n').split('\n')
    with open(args.template) as f:
        template = f.read()
    if template.count('---@translated\n') != 1:
        sys.exit('c2imp: the template must contain exactly one `---@translated` line')
    result = template.replace('---@translated\n', '\n'.join(program) + '\n')

    if args.target == '-':
        sys.stdout.write(result)
    else:
        with open(args.target, 'w') as f:
            f.write(result)


if __name__ == '__main__':
    main()
