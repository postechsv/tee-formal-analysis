#!/usr/bin/env python3
"""ta2imp: translate the C source of a trusted application into TEE-IMP programs.

Usage
    python3 tools/ta2imp.py case-studies/NAME/NAME.toml [--ta KEY] [--out FILE]

The [ta.KEY] table of the case-study manifest says what to translate and how (paths are relative to
the manifest):

    source     the C source (as published, or written for the model)
    patches    unified diffs applied to the source first: the modeling changes of the C code
    programs   {PROGRAM = [patch, ...]}: one TEE-IMP program per entry, from the source with
               `patches` and then the listed patches applied (a code-level fix is a patch here)
    functions  the functions to translate; the functions they call are translated too
    structs    the structs to translate (struct declarations come first)
    main       a TEE-IMP file appended to every program (the entry point of the model)
    template   the Maude file the programs are put in: each line `---@program PROGRAM` is replaced
               by the equation of that program
    output     the name of the generated file (default: KEY.maude)

    drop-calls          calls whose statements are left out (logging, timing, freeing memory)
    malloc-never-fails  `if (!x)` after `x = TEE_Malloc(...)` is left out
    [types]     "FUNCTION.VAR", "FUNCTION.PARAM" or "STRUCT.FIELD" -> TEE-IMP type, when the C
                type does not tell (e.g. `char *` is TEE-Buffer, TEE-ObjectId or TEE-Buffer &)
    [alias]     "FUNCTION.VAR" = "OTHER": VAR is another name of OTHER (a pointer to it); its
                declaration and its assignment `VAR = ...` are left out and VAR is renamed OTHER
    [drop-args] "FUNCTION" = [index, ...]: parameters left out of the definition and of every
                call (buffer sizes: the model has no sizes)
    drop-vars   ["FUNCTION.NAME", ...]: variables or parameters the model does not have; their
                declarations and every statement that mentions them (for an if, its condition)
                are left out.  An if condition that combines a dropped name with other terms by
                && or || is an error (change the condition in a patch).  A statement that
                mentions a parameter removed by [memref] or [drop-args] and not listed here is an
                error.
    [malloc]    "FUNCTION.VAR" = TEE-IMP value assigned by `VAR = TEE_Malloc(...)` (default # noData)
    [inline]    "FUNCTION.VAR" = TEE-IMP value: VAR is replaced by the value; its declaration
                and its assignments are left out
    [rewrite]   "C expression" = "C expression": replaced before translation (e.g. key sizes,
                which the model counts in bits)
    [assign]    "CALL" = "VAR": a statement that calls CALL assigns its result to VAR (a TEE
                API function that returns a value in the model only)
    [[insert]]  function, before (a called function), imp: a TEE-IMP statement put before the
                first statement that calls `before`
    [memref.FUNCTION]  how the TEE_Param memory references of FUNCTION map to model values:
                signature = "the TEE-IMP parameter list that replaces the C one",
                "C expression" = "model parameter" for each buffer (casts are ignored), e.g.
                "params[0].memref.buffer + TA_MQTTZ_CLI_ID_SZ" = "oriCliIv";
                "C expression" = "drop" for a TEE_Param field the model does not have: the
                statements that use it are left out.  Pointer arithmetic on a mapped buffer that
                has no entry of its own is an error.

Canonical form of the translation (no manifest entry needed): switch becomes an if/else chain,
a != b becomes ! (a == b), every if and else body is a block, and a call in an if condition or in
a return value is first assigned to a result variable (res when the function has one of the
callee's return type, else <callee>_res, declared once next to res or at the start of the body).
"""

import argparse
import os
import re
import subprocess
import sys
import tempfile
import tomllib

from tree_sitter import Language, Parser
import tree_sitter_c

# ---------------------------------------------------------------------------------------- tables

# C type -> TEE-IMP type.  Struct types of `structs` are added at run time.
C_TYPES = {
    'TEE_Result': 'TEE-Result',
    'TEE_Attribute': 'TEE-Attributes',
    'TEE_ObjectHandle': 'TEE-Handle',
    'TEE_OperationHandle': 'TEE-Handle',
    'TEE_ObjectInfo': 'struct TeeObjectInfo',
    'char': 'TEE-Buffer',          # only as char *
    'uint32_t': 'int',
    'size_t': 'int',
    'int': 'int',
    'void': 'void',
}

# TEE constants -> data constants of the model (written # value).
CONSTANTS = {
    'TEE_SUCCESS': 'success',
    'TEE_HANDLE_NULL': 'null',
    'TEE_ERROR_GENERIC': 'errorGeneric',
    'TEE_ERROR_BAD_PARAMETERS': 'errorBadParameters',
    'TEE_ERROR_BAD_STATE': 'errorBadState',
    'TEE_ERROR_OUT_OF_MEMORY': 'errorOutOfMemory',
    'TEE_ERROR_NOT_SUPPORTED': 'errorNotSupported',
    'TEE_ERROR_ITEM_NOT_FOUND': 'errorItemNotFound',
    'TEE_ERROR_SHORT_BUFFER': 'errorShortBuffer',
    'TEE_ALG_AES_CBC_NOPAD': 'algAesCbcNopad',
    'TEE_MODE_ENCRYPT': 'modeEncrypt',
    'TEE_MODE_DECRYPT': 'modeDecrypt',
    'TEE_TYPE_AES': 'typeAes',
    'TEE_ATTR_SECRET_VALUE': 'secretValue',
    'TEE_STORAGE_PRIVATE': 'storagePrivate',
    'NULL': 'noData',
}

# TEE_DATA_FLAG_* -> flag names of the model, written # (f1, f2, ...).
DATA_FLAGS = {
    'TEE_DATA_FLAG_ACCESS_READ': 'accessRead',
    'TEE_DATA_FLAG_ACCESS_WRITE': 'accessWrite',
    'TEE_DATA_FLAG_ACCESS_WRITE_META': 'accessWriteMeta',
    'TEE_DATA_FLAG_SHARE_READ': 'shareRead',
    'TEE_DATA_FLAG_SHARE_WRITE': 'shareWrite',
    'TEE_DATA_FLAG_OVERWRITE': 'overwrite',
}

# TEE API -> (TEE-IMP name, C arity, arguments).  An argument is the index of a C argument, or
# (index, wrapper): `# v` becomes `# wrapper(v)`.  Arities are those of GlobalPlatform.
API = {
    'TEE_AllocateOperation': ('allocOperation', 4, [1, 2, 3, 0]),
    'TEE_FreeOperation': ('freeOperation', 1, [0]),
    'TEE_ResetOperation': ('resetOperation', 1, [0]),
    'TEE_SetOperationKey': ('setOperationKey', 2, [0, 1]),
    'TEE_CipherInit': ('cipherInit', 3, [0, 1]),
    'TEE_CipherUpdate': ('cipherUpdate', 5, [0, 1, 3]),
    'TEE_AllocateTransientObject': ('allocateTransientObject', 3, [0, 1, 2]),
    'TEE_FreeTransientObject': ('freeTransientObject', 1, [0]),
    'TEE_ResetTransientObject': ('resetTransientObject', 1, [0]),
    'TEE_PopulateTransientObject': ('populateTransientObject', 3, [0, 1]),
    'TEE_InitRefAttribute': ('initRefAttribute', 4, [1, 2, 0]),
    'TEE_OpenPersistentObject': ('openPersistentObject', 5, [0, 1, 3, 4]),
    'TEE_CreatePersistentObject': ('createPersistent', 8, [0, 1, 3, 4, 5, (6, 'dataSize'), 7]),
    'TEE_GetObjectInfo1': ('getObjectInfo1', 2, [0, 1]),
    'TEE_ReadObjectData': ('readObjData', 4, [0, 2, 1]),
    'TEE_WriteObjectData': ('writeObjectData', 3, [0, 1]),
    'TEE_CloseObject': ('closeObject', 1, [0]),
    'TEE_CloseAndDeletePersistentObject1': ('closeAndDeletePersistentObject1', 1, [0]),
}
API_RESULT = 'TEE_Result'      # C return type of the API functions above that return a value

PARSER = Parser(Language(tree_sitter_c.language()))
DROP = '@drop@'      # translation of a [memref] entry "drop": the statement is left out
IND = '  '


class TransError(Exception):
    pass


def camel(name):
    parts = name.split('_')
    return parts[0] + ''.join(p[:1].upper() + p[1:] for p in parts[1:])


def pascal(name):
    return ''.join(p[:1].upper() + p[1:] for p in name.split('_'))


def text(n):
    return n.text.decode()


def norm(s):
    """C expression text without casts to pointer types and white space, for matching."""
    s = re.sub(r'\(\s*(?:const\s+)?(?:struct\s+)?\w+\s*\*\s*\)', '', s)
    return re.sub(r'\s+', '', s)


def named(n):
    return [c for c in n.children if c.is_named and c.type != 'comment']


# ------------------------------------------------------------------------------------- manifest

class Config(object):
    def __init__(self, table, base):
        self.t = table
        self.base = base
        self.drop_calls = set(table.get('drop-calls', []))
        self.malloc_safe = table.get('malloc-never-fails', False)
        self.types = table.get('types', {})
        self.alias = table.get('alias', {})
        self.drop_args = {k: set(v) for k, v in table.get('drop-args', {}).items()}
        self.drop_vars = set(table.get('drop-vars', []))
        self.malloc = table.get('malloc', {})
        self.inline = table.get('inline', {})
        self.rewrite = {norm(k): v for k, v in table.get('rewrite', {}).items()}
        self.assign = table.get('assign', {})
        self.insert = table.get('insert', [])
        self.memref = table.get('memref', {})
        self.used = set()      # manifest entries that were applied (unused ones are errors)

    def path(self, p):
        return os.path.join(self.base, p)

    def get(self, table, key):
        if key in table:
            self.used.add((id(table), key))
            return table[key]
        return None


# ----------------------------------------------------------------------------------- translator

class Func(object):
    def __init__(self, node):
        self.node = node
        decl = node.child_by_field_name('declarator')
        while decl.type == 'pointer_declarator':
            decl = decl.child_by_field_name('declarator')
        self.name = text(decl.child_by_field_name('declarator'))
        self.ret = base_type(node)
        self.params = []        # (C type node text, name, is pointer)
        for p in named(decl.child_by_field_name('parameters')):
            if p.type != 'parameter_declaration':
                continue
            d = p.child_by_field_name('declarator')
            if d is None:           # (void)
                continue
            name, ptr, arr = declarator_name(d)
            self.params.append((base_type(p), name, ptr or arr))
        self.body = node.child_by_field_name('body')


def base_type(n):
    t = n.child_by_field_name('type')
    s = text(t)
    return s.replace('struct ', '').strip()


def declarator_name(d):
    """(name, pointer?, array?) of a declarator."""
    ptr = arr = False
    while d is not None and d.type in ('pointer_declarator', 'array_declarator', 'init_declarator'):
        if d.type == 'pointer_declarator':
            ptr = True
        if d.type == 'array_declarator':
            arr = True
        d = d.child_by_field_name('declarator')
    return text(d), ptr, arr


class Translator(object):
    def __init__(self, cfg, src_text):
        self.cfg = cfg
        self.tree = PARSER.parse(src_text.encode())
        self.funcs, self.structs = {}, {}
        for n in self.tree.root_node.children:
            if n.type == 'function_definition':
                f = Func(n)
                self.funcs[f.name] = f
            elif n.type == 'type_definition':
                st = n.child_by_field_name('type')
                if st is not None and st.type == 'struct_specifier' and st.child_by_field_name('name'):
                    self.structs[text(st.child_by_field_name('name'))] = st
        self.done_ins = set()      # [[insert]] entries already placed in this program
        self.struct_types = {}
        for s in cfg.t.get('structs', []):
            if s not in self.structs:
                raise TransError('struct %s not found' % s)
            self.struct_types[s] = 'struct ' + pascal(s)

    # ---- types
    def imp_type(self, key, ctype, ptr):
        t = self.cfg.get(self.cfg.types, key)
        if t is not None:
            return t
        if ctype in self.struct_types:
            return self.struct_types[ctype]
        if ctype in C_TYPES:
            return C_TYPES[ctype]
        raise TransError('%s: no TEE-IMP type for C type %s%s; add it to [types]'
                         % (key, ctype, ' *' if ptr else ''))

    # ---- program
    def selected(self):
        roots = self.cfg.t.get('functions', [])
        order, seen = [], set()

        def visit(name):
            if name in seen:
                return
            seen.add(name)
            f = self.funcs[name]
            for c in walk(f.body):
                if c.type == 'call_expression':
                    callee = text(c.child_by_field_name('function'))
                    if callee in self.cfg.drop_calls:
                        self.cfg.used.add(('call', callee))
                    elif callee in self.funcs:
                        visit(callee)
            order.append(name)
        for r in roots:
            if r not in self.funcs:
                raise TransError('function %s not found' % r)
            visit(r)
        src_order = [n for n in self.funcs if n in seen]
        return src_order

    def program(self):
        out = []
        for s in self.cfg.t.get('structs', []):
            out += self.struct(s) + ['']
        for name in self.selected():
            f = self.funcs[name]
            bad = [n for n in walk(f.node) if n.type == 'ERROR' or n.is_missing]
            if bad:
                raise TransError('%s: C parse error at line %d' % (name, bad[0].start_point[0] + 1))
            out += self.function(f) + ['']
        return out

    def struct(self, name):
        body = self.structs[name].child_by_field_name('body')
        lines = ['%s {' % self.struct_types[name]]
        for fd in named(body):
            if fd.type != 'field_declaration':
                continue
            fname, ptr, _ = declarator_name(fd.child_by_field_name('declarator'))
            lines.append(IND + '%s %s ;' % (self.imp_type('%s.%s' % (name, fname), base_type(fd), ptr),
                                            camel(fname)))
        return lines + ['} ;']

    def function(self, f):
        self.f = f
        self.locals = {}            # C name -> C type
        drops = self.cfg.drop_args.get(f.name, set())
        if drops:
            self.cfg.used.add((id(self.cfg.drop_args), f.name))
        mem = self.cfg.memref.get(f.name)
        self.removed = set()
        self.memmap = {}
        if mem is not None:
            self.cfg.used.add((id(self.cfg.memref), f.name))
            sig = mem['signature']
            keep = {n.split()[-1] for n in sig.split(',')}
            self.removed = {n for _, n, _ in f.params if camel(n) not in keep}
            self.memmap = {norm(k): v for k, v in mem.items() if k != 'signature'}
            for _, n, _ in f.params:
                if n not in self.removed:
                    self.locals[n] = None
        else:
            ps = []
            for k, (ct, n, ptr) in enumerate(f.params):
                if k in drops:
                    self.removed.add(n)
                    continue
                self.locals[n] = ct
                ps.append('%s %s' % (self.imp_type('%s.%s' % (f.name, n), ct, ptr), camel(n)))
            sig = ', '.join(ps)
        self.mallocs = set()
        self.aliases = {}
        for k, v in self.cfg.alias.items():
            fn, var = k.split('.', 1)
            if fn == f.name:
                self.cfg.used.add((id(self.cfg.alias), k))
                self.aliases[var] = v
        self.inlines = {}
        for k, v in self.cfg.inline.items():
            fn, var = k.split('.', 1)
            if fn == f.name:
                self.cfg.used.add((id(self.cfg.inline), k))
                self.inlines[var] = v
        self.dropped = {k.split('.', 1)[1] for k in self.cfg.drop_vars if k.split('.', 1)[0] == f.name}
        for k in self.cfg.drop_vars:
            if k.split('.', 1)[0] == f.name:
                self.cfg.used.add((id(self.cfg.drop_vars), k))
        for n in walk(f.body):
            if n.type == 'declaration':
                for d in n.children_by_field_name('declarator'):
                    nm, ptr, _ = declarator_name(d)
                    self.locals[nm] = base_type(n)
        self.result_vars = []       # (C name, C type) of result variables to declare
        self.declared_res = {}
        body = self.block(f.body, 1)
        # result variables: next to res when it is declared, else first
        decls = [IND + '%s %s ;' % (self.imp_type('%s.%s' % (f.name, n), t, False), camel(n))
                 for n, t in self.result_vars]
        if decls:
            at = next((k + 1 for k, ln in enumerate(body) if re.match(r'^\s*TEE-Result res ;$', ln)), 0)
            body[at:at] = decls
        head = '%s %s (%s)' % (self.imp_type('%s.return' % f.name, f.ret, False), camel(f.name), sig)
        return [head, '{'] + body + ['}']

    # ---- statements
    def block(self, node, depth):
        out = []
        items = named(node) if node.type == 'compound_statement' else [node]
        for s in items:
            out += self.stmt(s, depth)
        return out

    def gone(self, lines):
        """True when the translated lines mention a variable of drop-vars (the statement is left
        out); an error when they mention a parameter removed by [memref] or [drop-args] that
        drop-vars does not list."""
        txt = ' '.join(lines)
        has = lambda n: re.search(r'(?<![\w-])%s(?![\w-])' % re.escape(camel(n)), txt) is not None
        if DROP in txt or any(has(n) for n in self.dropped):
            return True
        bad = sorted(n for n in self.removed - self.dropped if has(n))
        if bad:
            raise TransError('%s: %s mentions the removed parameter(s) %s; map it in [memref] or '
                             'list it in drop-vars' % (self.f.name, txt.strip()[:70], ', '.join(bad)))
        return False

    def stmt(self, s, depth):
        pad = IND * depth
        t = s.type
        if t == 'comment':
            return []
        if t == 'declaration':
            return self.declaration(s, depth)
        if t == 'expression_statement':
            e = named(s)
            if not e:
                return []
            e = e[0]
            if e.type == 'call_expression':
                callee = text(e.child_by_field_name('function'))
                if callee in self.cfg.drop_calls:
                    self.cfg.used.add(('call', callee))
                    return []
                var = self.cfg.assign.get(callee)
                line = pad + ('%s := %s ;' % (camel(var), self.expr(e)) if var else '%s ;' % self.expr(e))
                if self.gone([line]):
                    return []
                if var:
                    self.cfg.used.add((id(self.cfg.assign), callee))
                return self.inserts(callee, depth) + [line]
            if e.type == 'assignment_expression':
                out = self.assignment(e, depth)
                return [] if self.gone(out) else out
            raise TransError('%s: unsupported statement %s' % (self.f.name, text(s)[:60]))
        if t == 'if_statement':
            cond = s.child_by_field_name('condition')
            if self.malloc_check(cond):
                return []
            pre, c = self.hoist(cond, depth)
            if self.gone(pre + [c]):
                self.mixed_condition(cond)
                return []
            out = pre + [pad + 'if (%s) {' % c]
            out += self.block(s.child_by_field_name('consequence'), depth + 1)
            alt = s.child_by_field_name('alternative')
            if alt is not None:
                alt = named(alt)[0] if alt.type == 'else_clause' else alt
                out += [pad + '} else {'] + self.block(alt, depth + 1)
            return out + [pad + '}']
        if t == 'switch_statement':
            return self.switch(s, depth)
        if t == 'return_statement':
            e = named(s)
            if not e:
                return [pad + 'return ;']
            e = e[0]
            if self.gone([self.expr(e)]):
                return []
            if self.contains_call(e):
                var = self.result_var_for(e, declare_here=True)
                out = []
                if var[1]:
                    out.append(pad + '%s %s ;' % (self.imp_type('%s.%s' % (self.f.name, var[0]), var[2], False),
                                                 camel(var[0])))
                return out + [pad + '%s := %s ;' % (camel(var[0]), self.expr(e)), pad + 'return %s ;' % camel(var[0])]
            return [pad + 'return %s ;' % self.expr(e)]
        if t == 'goto_statement':
            return [pad + 'goto %s ;' % text(named(s)[0])]
        if t == 'labeled_statement':
            lab = text(s.child_by_field_name('label'))
            return [pad + '%s :' % lab] + self.stmt(named(s)[-1], depth + 1)
        if t == 'compound_statement':
            return self.block(s, depth)
        if t == 'break_statement':
            return []
        raise TransError('%s: unsupported statement %s: %s' % (self.f.name, t, text(s)[:60]))

    def mixed_condition(self, cond):
        """An error when a condition left out because of a dropped name has && or || operands
        that do not mention one: leaving it out would also drop those tests."""
        c = strip_parens(cond)
        if c.type == 'binary_expression' and text(c.child_by_field_name('operator')) in ('&&', '||'):
            ops = []

            def flat(e):
                e = strip_parens(e)
                if e.type == 'binary_expression' and text(e.child_by_field_name('operator')) in ('&&', '||'):
                    flat(e.child_by_field_name('left'))
                    flat(e.child_by_field_name('right'))
                else:
                    ops.append(e)
            flat(c)
            keep = [o for o in ops if not self.gone([self.expr(o)])]
            if keep:
                raise TransError('%s: the condition %s is left out for a dropped name, but %s does not '
                                 'mention one; change the condition in a patch'
                                 % (self.f.name, text(cond), text(keep[0])))

    def inserts(self, callee, depth):
        out = []
        for k, ins in enumerate(self.cfg.insert):
            if ins['function'] == self.f.name and ins['before'] == callee and k not in self.done_ins:
                self.done_ins.add(k)
                self.cfg.used.add(('ins', k))
                out.append(IND * depth + ins['imp'])
        return out

    def declaration(self, s, depth):
        out = []
        for d in s.children_by_field_name('declarator'):
            name, ptr, arr = declarator_name(d)
            if name in self.dropped or name in self.aliases or name in self.inlines:
                continue
            if arr:
                raise TransError('%s: array %s; list it in drop-vars' % (self.f.name, name))
            ct = base_type(s)
            out.append(IND * depth + '%s %s ;' % (self.imp_type('%s.%s' % (self.f.name, name), ct, ptr), camel(name)))
            if d.type == 'init_declarator':
                v = d.child_by_field_name('value')
                init = self.assign_value(name, v, depth)
                if self.gone(init):
                    raise TransError('%s: the initializer of %s mentions a dropped variable' % (self.f.name, name))
                out += init
        return out

    def assignment(self, e, depth):
        lhs, rhs = e.child_by_field_name('left'), e.child_by_field_name('right')
        if e.child_by_field_name('operator') is not None and text(e.child_by_field_name('operator')) != '=':
            raise TransError('%s: compound assignment %s' % (self.f.name, text(e)))
        if lhs.type == 'identifier' and (text(lhs) in self.aliases or text(lhs) in self.inlines):
            return []
        out = self.assign_value(lhs, rhs, depth)
        if self.gone(out):
            return []
        return (self.inserts(self.call_name(rhs), depth) if self.call_name(rhs) else []) + out

    def assign_value(self, lhs, rhs, depth):
        name = lhs if isinstance(lhs, str) else None
        target = camel(lhs) if name else self.expr(lhs)
        if self.call_name(rhs) == 'TEE_Malloc':
            var = name or text(lhs)
            self.mallocs.add(var)
            v = self.cfg.get(self.cfg.malloc, '%s.%s' % (self.f.name, var))
            return [IND * depth + '%s := %s ;' % (target, v or '# noData')]
        return [IND * depth + '%s := %s ;' % (target, self.expr(rhs))]

    def call_name(self, e):
        while e is not None and e.type in ('cast_expression', 'parenthesized_expression'):
            e = named(e)[-1]
        if e is not None and e.type == 'call_expression':
            return text(e.child_by_field_name('function'))
        return None

    def malloc_check(self, cond):
        if not self.cfg.malloc_safe:
            return False
        t = norm(text(cond))
        m = re.match(r'^\(?!\(?(\w+)\)?\)?$', t) or re.match(r'^\(?\(?(\w+)\)?==NULL\)?$', t)
        return bool(m and (m.group(1) in self.mallocs or m.group(1) in self.inlines))

    def switch(self, s, depth):
        subj = self.expr(strip_parens(s.child_by_field_name('condition')))
        cases = [c for c in named(s.child_by_field_name('body')) if c.type == 'case_statement']

        def chain(k, d):
            c = cases[k]
            value = c.child_by_field_name('value')
            body = [x for x in named(c) if value is None or x.start_byte != value.start_byte]
            stmts = []
            for b in body:
                stmts += self.stmt(b, d + 1)
            if value is None:
                return stmts if k else [IND * d + '{'] + stmts + [IND * d + '}']
            head = [IND * d + 'if (%s == %s) {' % (subj, self.expr(value))] + stmts
            if k + 1 < len(cases):
                rest = chain(k + 1, d + 1)
                return head + [IND * d + '} else {'] + rest + [IND * d + '}']
            return head + [IND * d + '}']
        return chain(0, depth)

    # ---- result variables
    def contains_call(self, e):
        return any(c.type == 'call_expression' and text(c.child_by_field_name('function')) not in self.cfg.drop_calls
                   for c in walk(e))

    def callee_type(self, call):
        callee = text(call.child_by_field_name('function'))
        if callee in API:
            return API_RESULT
        if callee in self.funcs:
            return self.funcs[callee].ret
        raise TransError('%s: unknown function %s' % (self.f.name, callee))

    def result_var_for(self, call, declare_here=False):
        if call.type != 'call_expression':
            call = next(c for c in walk(call) if c.type == 'call_expression')
        ct = self.callee_type(call)
        if self.locals.get('res') == ct or ('res' in self.declared_res and self.declared_res['res'] == ct):
            return ('res', False, ct)
        if declare_here and ct == 'TEE_Result':
            self.declared_res['res'] = ct
            return ('res', True, ct)
        name = text(call.child_by_field_name('function')) + '_res'
        if (name, ct) not in self.result_vars:
            self.result_vars.append((name, ct))
        return (name, False, ct)

    def hoist(self, cond, depth):
        """Assignments of the calls of the condition to result variables, and the condition."""
        calls = [c for c in walk(cond) if c.type == 'call_expression'
                 and text(c.child_by_field_name('function')) not in self.cfg.drop_calls]
        pre, sub = [], {}
        for c in calls:
            if any(o is not c and c.start_byte >= o.start_byte and c.end_byte <= o.end_byte for o in calls):
                continue
            var, _, _ = self.result_var_for(c)
            pre += self.inserts(text(c.child_by_field_name('function')), depth)
            pre.append(IND * depth + '%s := %s ;' % (camel(var), self.expr(c)))
            sub[(c.start_byte, c.end_byte)] = camel(var)
        return pre, self.expr(strip_parens(cond), sub)

    # ---- expressions
    def expr(self, e, sub=None):
        sub = sub or {}
        if (e.start_byte, e.end_byte) in sub:
            return sub[(e.start_byte, e.end_byte)]
        nt = norm(text(e))
        if nt in self.memmap:
            self.cfg.used.add(('mem', self.f.name, nt))
            return DROP if self.memmap[nt] == 'drop' else self.memmap[nt]
        if e.type == 'binary_expression' and text(e.child_by_field_name('operator')) in ('+', '-'):
            base = norm(text(e.child_by_field_name('left')))
            if any(base == k or base.startswith(k + '+') for k in self.memmap):
                raise TransError('%s: %s is an offset into a memory reference without an entry of its '
                                 'own in [memref.%s]' % (self.f.name, text(e), self.f.name))
        rw = self.cfg.rewrite.get(nt)
        if rw is not None:
            self.cfg.used.add((id(self.cfg.rewrite), nt))
            return self.expr(PARSER.parse(('int __x = %s;' % rw).encode()).root_node
                             .children[0].child_by_field_name('declarator').child_by_field_name('value'), sub)
        t = e.type
        if t == 'identifier':
            n = text(e)
            if n in self.inlines:
                return self.inlines[n]
            if n in self.aliases:
                return camel(self.aliases[n])
            if n in CONSTANTS:
                return '# %s' % CONSTANTS[n]
            if n in DATA_FLAGS:
                return '# (%s)' % DATA_FLAGS[n]
            if n in self.locals or n in self.funcs:
                return camel(n)
            if re.match(r'^[A-Z][A-Z0-9_]*$', n):
                return '# %s' % n.replace('_', '-')
            return camel(n)
        if t == 'null':
            return '# %s' % CONSTANTS['NULL']
        if t in ('true', 'false'):
            return '# %s' % t
        if t == 'number_literal':
            return '# %s' % text(e)
        if t == 'string_literal':
            raise TransError('%s: string literal %s' % (self.f.name, text(e)))
        if t in ('parenthesized_expression',):
            inner = self.expr(named(e)[0], sub)
            return '(%s)' % inner
        if t == 'cast_expression':
            return self.expr(e.child_by_field_name('value'), sub)
        if t == 'pointer_expression':
            return self.expr(e.child_by_field_name('argument'), sub)
        if t == 'field_expression':
            return '%s . %s' % (self.expr(e.child_by_field_name('argument'), sub),
                                camel(text(e.child_by_field_name('field'))))
        if t == 'unary_expression':
            op = text(e.child_by_field_name('operator'))
            arg = e.child_by_field_name('argument')
            return '%s %s' % (op, self.expr(arg, sub)) if op == '!' else '%s%s' % (op, self.expr(arg, sub))
        if t == 'binary_expression':
            op = text(e.child_by_field_name('operator'))
            l, r = e.child_by_field_name('left'), e.child_by_field_name('right')
            if op == '|':
                flags = flag_list(e)
                if flags is not None:
                    return '# (%s)' % ', '.join(DATA_FLAGS[f] for f in flags)
            if op == '!=':
                return '! (%s == %s)' % (self.expr(l, sub), self.expr(r, sub))
            return '%s %s %s' % (self.expr(l, sub), op, self.expr(r, sub))
        if t == 'call_expression':
            return self.call(e, sub)
        if t == 'subscript_expression':
            return '%s[%s]' % (self.expr(e.child_by_field_name('argument'), sub),
                               self.expr(e.child_by_field_name('index'), sub))
        raise TransError('%s: unsupported expression %s: %s' % (self.f.name, t, text(e)[:60]))

    def call(self, e, sub):
        callee = text(e.child_by_field_name('function'))
        args = named(e.child_by_field_name('arguments'))
        if callee in API:
            name, arity, spec = API[callee]
            if len(args) != arity:
                raise TransError('%s: %s takes %d arguments, not %d' % (self.f.name, callee, arity, len(args)))
            out = []
            for a in spec:
                if isinstance(a, tuple):
                    v = self.expr(args[a[0]], sub)
                    out.append('# %s(%s)' % (a[1], v[2:]) if v.startswith('# ') else v)
                else:
                    out.append(self.expr(args[a], sub))
            return '%s(%s)' % (name, ', '.join(out))
        if callee in self.funcs:
            drops = self.cfg.drop_args.get(callee, set())
            return '%s(%s)' % (camel(callee), ', '.join(self.expr(a, sub) for k, a in enumerate(args) if k not in drops))
        raise TransError('%s: call of %s, which is neither translated nor a TEE API function the '
                         'translator knows; add it to drop-calls or to the API table'
                         % (self.f.name, callee))


def flag_list(e):
    if e.type == 'identifier':
        return [text(e)] if text(e) in DATA_FLAGS else None
    if e.type == 'parenthesized_expression':
        return flag_list(named(e)[0])
    if e.type == 'binary_expression' and text(e.child_by_field_name('operator')) == '|':
        l, r = flag_list(e.child_by_field_name('left')), flag_list(e.child_by_field_name('right'))
        return l + r if l is not None and r is not None else None
    return None


def strip_parens(e):
    while e.type == 'parenthesized_expression' and len(named(e)) == 1:
        e = named(e)[0]
    return e


def walk(n):
    yield n
    for c in n.children:
        yield from walk(c)


# ------------------------------------------------------------------------------------------ main

def apply_patches(src, patches):
    with open(src, encoding='utf-8') as fh:
        cur = fh.read()
    for p in patches:
        with tempfile.TemporaryDirectory() as d:
            a = os.path.join(d, 'in.c')
            with open(a, 'w', encoding='utf-8') as fh:
                fh.write(cur)
            r = subprocess.run(['patch', '--quiet', '--no-backup-if-mismatch', '-o', os.path.join(d, 'out.c'),
                                a, p], capture_output=True, text=True)
            if r.returncode:
                raise TransError('patch %s does not apply: %s%s' % (p, r.stdout, r.stderr))
            with open(os.path.join(d, 'out.c'), encoding='utf-8') as fh:
                cur = fh.read()
    return cur


def translate(manifest, key, out_path=None):
    with open(manifest, 'rb') as fh:
        data = tomllib.load(fh)
    base = os.path.dirname(os.path.abspath(manifest))
    table = data['ta'][key]
    cfg = Config(table, base)
    with open(cfg.path(table['main']), encoding='utf-8') as fh:
        main = fh.read().rstrip('\n').split('\n')
    bodies = {}
    for prog, extra in table['programs'].items():
        src = apply_patches(cfg.path(table['source']), [cfg.path(p) for p in table.get('patches', []) + extra])
        tr = Translator(cfg, src)
        lines = tr.program() + main
        bodies[prog] = '\n'.join(('    ' + ln) if ln else '' for ln in lines)
    unused = []
    for name, tab in (('types', cfg.types), ('alias', cfg.alias), ('drop-args', cfg.drop_args),
                      ('malloc', cfg.malloc), ('inline', cfg.inline), ('rewrite', cfg.rewrite),
                      ('assign', cfg.assign)):
        unused += ['[%s] %s' % (name, k) for k in tab if (id(tab), k) not in cfg.used]
    unused += ['drop-vars %s' % k for k in cfg.drop_vars if (id(cfg.drop_vars), k) not in cfg.used]
    unused += ['drop-calls %s' % k for k in cfg.drop_calls if ('call', k) not in cfg.used]
    unused += ['[[insert]] %d' % k for k in range(len(cfg.insert)) if ('ins', k) not in cfg.used]
    for fn, mem in cfg.memref.items():
        unused += ['[memref.%s] %s' % (fn, k) for k in mem if k != 'signature' and ('mem', fn, norm(k)) not in cfg.used]
    if unused:
        raise TransError('manifest entries that match nothing: ' + '; '.join(sorted(unused)))
    with open(cfg.path(table['template']), encoding='utf-8') as fh:
        tmpl = fh.read()
    for prog, body in bodies.items():
        marker = '---@program %s' % prog
        if tmpl.count(marker) != 1:
            raise TransError('template: expected one line %s' % marker)
        tmpl = tmpl.replace(marker, '  eq %s =\n\n%s\n  .' % (prog, body))
    out_path = out_path or os.path.join(base, table.get('output', key + '.maude'))
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, 'w', encoding='utf-8') as fh:
        fh.write(tmpl)
    return out_path


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('manifest')
    ap.add_argument('--ta', help='key of the [ta.KEY] table (default: every one)')
    ap.add_argument('--out', help='output file (only with one TA); default: its output entry')
    args = ap.parse_args(argv)
    with open(args.manifest, 'rb') as fh:
        keys = [args.ta] if args.ta else list(tomllib.load(fh).get('ta', {}))
    try:
        for k in keys:
            print('ta2imp: %s' % translate(args.manifest, k, args.out))
    except TransError as ex:
        sys.stderr.write('ta2imp: error: %s\n' % ex)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
