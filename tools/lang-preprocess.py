#!/usr/bin/env python3
"""preprocess: preprocess the C source of a trusted application, or of the rich application that
calls it, into the programs of the model.

Usage
    python3 tools/lang-preprocess.py NAME/NAME.toml [--ta KEY | --ra KEY] [--out FILE]

The [ta.KEY] table of the case-study manifest (a TA), or the [ra.KEY] table (an RA), says what to
preprocess and how (paths are relative to the manifest):

    source     the C source (as published, or written for the model), or a list of C files
               (headers and sources) that are concatenated in order into one translation unit
               before the patches are applied
    patches    unified diffs applied to the source first: the modeling changes of the C code
    programs   {PROGRAM = [patch, ...]}: one model program per entry, from the source with
               `patches` and then the listed patches applied (a code-level fix is a patch here)
    functions  the functions to keep; the functions they call are kept too
    globals    the global variables to keep: scalars of a base type or of a TEE handle type,
               and arrays of them (a C
               array size is a number or a name that a #define of the source gives a number).
               Each is declared at the top of the program and set to 0 (false for a bool, null
               for a handle), as
               C initializes a static object; the model keeps their values from one command to
               the next (the instance memory of the TA)
    structs    the structs to keep (struct declarations come first)
    entry      the C function that serves the commands of a TA (TA_InvokeCommandEntryPoint): the
               entry point of the model (see Entry point below)
    main       instead of entry: a file in the model's syntax appended to every program (the entry
               point of an RA)
    template   the Maude file the programs are put in: each line `---@program PROGRAM` is replaced
               by the equation of that program
    output     the name of the generated file (default: KEY.maude)

    drop-calls          calls whose statements are left out (logging, timing, freeing memory)
    malloc-never-fails  `if (!x)` after `x = TEE_Malloc(...)` is left out
    [c-types]   "C type" = "model type": C types (typedefs) added to the built-in table
    [types]     "FUNCTION.VAR", "FUNCTION.PARAM" or "STRUCT.FIELD" -> model type, when the C
                type alone is not the one the model needs (none is needed for MQT-TZ)
    [drop-args] "FUNCTION" = [index, ...]: parameters left out of the definition and of every
                call (buffer sizes: the model has no sizes)
    drop-vars   ["FUNCTION.NAME", ...]: variables or parameters the model does not have; their
                declarations and every statement that mentions them (for an if, its condition)
                are left out.  An if condition that combines a dropped name with other terms by
                && or || is an error (change the condition in a patch).  A statement that
                mentions a parameter removed by [memref] or [drop-args] and not listed here is an
                error.
    [malloc]    "FUNCTION.VAR" = the initial content of the buffer of `VAR = TEE_Malloc(...)`
                (default # zeroData: the hint 0 is TEE_MALLOC_FILL_ZERO, the only one supported);
                the statement becomes VAR := malloc(content) ;
    [inline]    "FUNCTION.VAR" = model value: VAR is replaced by the value; its declaration
                and its assignments are left out
    [rewrite]   "C expression" = "C expression": replaced before preprocessing (e.g. key sizes,
                which the model counts in bits)
    [assign]    "CALL" = "VAR": a statement that calls CALL assigns its result to VAR (a TEE
                API function that returns a value in the model only)
    [[insert]]  function, before (a called function), c: a model statement put before the
                first statement that calls `before`
    [invoke]    the TEEC_InvokeCommand calls of an RA: entry = the TA function that serves the
                command (the model calls it with the command as its first argument), ta-result =
                the variable that gets the return code of the TA (its output parameter, the last
                argument; see Client calls below)
    [memref.FUNCTION]  how the TEE_Param memory references of FUNCTION map to model values:
                signature = "the model parameter list that replaces the C one",
                "C expression" = "model parameter" for each buffer (casts are ignored), e.g.
                "params[0].memref.buffer + TA_MQTTZ_CLI_ID_SZ" = "oriCliIv";
                "C expression" = "drop" for a TEE_Param field the model does not have: the
                statements that use it are left out.  Pointer arithmetic on a mapped buffer that
                has no entry of its own is an error.

Pointers are kept as they are: a pointer to void, char, a kept struct or an int type
is a model pointer type (void *, char *, (struct S) *, int *), &x is addr(x), *p is deref(p),
p->f is p -> f, NULL is nullptr, and casts are left out (void * converts to and from any pointer
type, as in C).  A buffer is one object of type char that holds its whole content: TEE_Malloc
becomes malloc(content), an object in the frame of the calling function (see [malloc]).  So a
TEE_Malloc pointer must not outlive that function: returning it, or storing it anywhere but in a
local variable of the function, is an error.  The arguments of a TEE API call are passed as the
model's stubs take them: an output argument &x of a handle, a struct or an int is the lvalue x,
and a buffer is passed as the pointer it is.

Client calls (an RA).  A TEEC_Operation variable op is not a model object: the assignments
op.params[i].tmpref.buffer = X collect the memory references of the operation, and the other fields
(paramTypes, the sizes) are left out, as the model has no parameter types and no sizes.  The call
res = TEEC_InvokeCommand(&sess, CMD, &op, &origin) becomes
    res := teecInvokeCommand(sess, # ENTRY, (CMD, X0, X1, ..., addr(TA-RESULT))) ;
with ENTRY and TA-RESULT of [invoke]: the TA runs on the memory of the RA, so a buffer X is passed as
the pointer it is, and the TA writes its return code to TA-RESULT.  The call returns success, or
TEE_ERROR_TARGET_DEAD when the TA panicked; the return origin is not modeled (list it in drop-vars).

Entry point (a TA).  The entry function becomes void main (PARAMS, TEE-Result & ret), the function
that the RA invokes ([invoke] entry = "main"): PARAMS is the signature of its [memref] table, which
maps the TEE_Param memory references (the parameter types are not modeled: list param_types in
drop-vars).  A return E is ret := E ; followed by return unit ;.  The globals are the instance
memory of the TA: main loads them with loadGlobals(G1, ..., Gn) when it starts and stores them with
storeGlobals(G1, ..., Gn) before every return (an array global is its elements, in order).

Canonical form of the output (no manifest entry needed): switch becomes an if/else chain,
a != b becomes ! (a == b), a < b, a > b and a >= b become <= with !, a % b becomes a - (a / b) * b,
for and while loops become while (a break is a goto past the loop), x++ is x := x + 1, every if and else body is a block, and a call in an if condition or in
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

# C type -> model type.  Struct types of `structs` are added at run time.
C_TYPES = {
    'TEE_Result': 'TEE-Result',
    'TEEC_Result': 'TEE-Result',
    'TEEC_Session': 'TEEC-Session',
    'TEE_Attribute': 'TEE-Attribute',
    'TEE_ObjectHandle': 'TEE-ObjectHandle',
    'TEE_OperationHandle': 'TEE-OperationHandle',
    'TEE_ObjectInfo': 'struct TeeObjectInfo',
    'TEE_Time': 'struct TeeTime',
    'char': 'char',                # the content of a buffer (char * points to it)
    'uint32_t': 'int',
    'size_t': 'int',
    'int': 'int',
    'void': 'void',
}

# TEE constants -> data constants of the model (written # value).
CONSTANTS = {
    'TEE_SUCCESS': 'success',
    'TEEC_SUCCESS': 'success',
    'TEEC_ERROR_TARGET_DEAD': 'errorTargetDead',
    'TEE_HANDLE_NULL': 'null',
    'TEE_ERROR_GENERIC': 'errorGeneric',
    'TEE_ERROR_BAD_PARAMETERS': 'errorBadParameters',
    'TEE_ERROR_BAD_STATE': 'errorBadState',
    'TEE_ERROR_OUT_OF_MEMORY': 'errorOutOfMemory',
    'TEE_ERROR_NOT_SUPPORTED': 'errorNotSupported',
    'TEE_ERROR_ITEM_NOT_FOUND': 'errorItemNotFound',
    'TEE_ERROR_SHORT_BUFFER': 'errorShortBuffer',
    'TEE_ERROR_MAC_INVALID': 'errorMacInvalid',
    # a storage failure is returned as the storage status (# STATUS, as in the paper)
    'TEE_ERROR_CORRUPT_OBJECT': 'corrupted',
    'TEE_ERROR_STORAGE_NOT_AVAILABLE': 'notAvailable',
    'TEE_ERROR_STORAGE_NO_SPACE': 'outOfSpace',
    'TEE_ERROR_CORRUPT_OBJECT_2': 'errorCorruptObject2',
    'TEE_ERROR_STORAGE_NOT_AVAILABLE_2': 'errorStorageNotAvailable2',
    'TEE_ALG_AES_CBC_NOPAD': 'algAesCbcNopad',
    'TEE_ALG_HMAC_SHA256': 'algHmacSha256',
    'TEE_MODE_MAC': 'modeMac',
    'TEE_TYPE_HMAC_SHA256': 'typeHmacSha256',
    'TEE_MODE_ENCRYPT': 'modeEncrypt',
    'TEE_MODE_DECRYPT': 'modeDecrypt',
    'TEE_TYPE_AES': 'typeAes',
    'TEE_ATTR_SECRET_VALUE': 'secretValue',
    'TEE_STORAGE_PRIVATE': 'storagePrivate',
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

# TEE API -> (model name, C arity, arguments).  An argument is the index of a C argument, or
# (index, wrapper): `# v` becomes `# wrapper(v)`, or ('ptr', index): a buffer, passed as the pointer
# it is (&x is addr(x)) where the other arguments pass &x as the lvalue x.  Arities are those of
# GlobalPlatform.
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
    'TEE_InitRefAttribute': ('initRefAttribute', 4, [1, ('ptr', 2), 0]),
    'TEE_OpenPersistentObject': ('openPersistentObject', 5, [0, ('ptr', 1), 3, 4]),
    'TEE_CreatePersistentObject': ('createPersistent', 8, [0, 1, 3, 4, 5, 6, 7]),
    'TEE_GetObjectInfo1': ('getObjectInfo1', 2, [0, 1]),
    'TEE_ReadObjectData': ('readObjData', 4, [0, 2, ('ptr', 1)]),
    'TEE_WriteObjectData': ('writeObjectData', 3, [0, ('ptr', 1)]),
    'TEE_CloseObject': ('closeObject', 1, [0]),
    'TEE_CloseAndDeletePersistentObject1': ('closeAndDeletePersistentObject1', 1, [0]),
    'TEE_MACInit': ('macInit', 3, [0, ('ptr', 1)]),
    'TEE_MACUpdate': ('macUpdate', 3, [0, ('ptr', 1)]),
    'TEE_MACComputeFinal': ('macComputeFinal', 5, [0, ('ptr', 1), ('ptr', 3)]),
    'TEE_MACCompareFinal': ('macCompareFinal', 5, [0, ('ptr', 1), ('ptr', 3)]),
    'TEE_GenerateRandom': ('generateRandom', 2, [('ptr', 0)]),
    'TEE_GetSystemTime': ('getSystemTime', 1, [0]),
}
API_RESULT = 'TEE_Result'      # C return type of the API functions above that return a value
TEEC_OPERATION = 'TEEC_Operation'
TEEC_INVOKE = 'TEEC_InvokeCommand'

PARSER = Parser(Language(tree_sitter_c.language()))
DROP = '@drop@'      # output of a [memref] entry "drop": the statement is left out
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
        self.ctypes = dict(C_TYPES, **table.get('c-types', {}))
        self.globals = table.get('globals', [])
        self.drop_args = {k: set(v) for k, v in table.get('drop-args', {}).items()}
        self.drop_vars = set(table.get('drop-vars', []))
        self.malloc = table.get('malloc', {})
        self.inline = table.get('inline', {})
        self.rewrite = {norm(k): v for k, v in table.get('rewrite', {}).items()}
        self.assign = table.get('assign', {})
        self.insert = table.get('insert', [])
        self.memref = table.get('memref', {})
        self.invoke = table.get('invoke')
        self.entry = table.get('entry')
        self.used = set()      # manifest entries that were applied (unused ones are errors)

    def path(self, p):
        return os.path.join(self.base, p)

    def get(self, table, key):
        if key in table:
            self.used.add((id(table), key))
            return table[key]
        return None


# --------------------------------------------------------------------------------- preprocessor

class Func(object):
    def __init__(self, node):
        self.node = node
        decl = node.child_by_field_name('declarator')
        self.ret_ptr = decl.type == 'pointer_declarator'     # returns a pointer (void * f(...))
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
        # __unused (OP-TEE's __attribute__((unused))) is a macro that the parser does not know
        src_text = re.sub(r'\b__unused\b', '', src_text)
        self.tree = PARSER.parse(src_text.encode())
        self.funcs, self.structs = {}, {}
        self.decls, self.defines = {}, {}
        for n in walk(self.tree.root_node):
            if n.type == 'preproc_def' and n.child_by_field_name('value') is not None:
                v = text(n.child_by_field_name('value')).strip()
                if re.fullmatch(r'\d+U?', v):
                    self.defines[text(n.child_by_field_name('name'))] = int(v.rstrip('U'))
        for n in top_level(self.tree.root_node):
            if n.type == 'declaration':
                for d in n.children_by_field_name('declarator'):
                    self.decls[declarator_name(d)[0]] = (n, d)
            if n.type == 'function_definition':
                f = Func(n)
                self.funcs[f.name] = f
            elif n.type == 'type_definition':
                st = n.child_by_field_name('type')
                if st is not None and st.type == 'struct_specifier' and st.child_by_field_name('body'):
                    # typedef struct NAME {...} T; is found as NAME and as T
                    if st.child_by_field_name('name'):
                        self.structs[text(st.child_by_field_name('name'))] = st
                    for d in n.children_by_field_name('declarator'):
                        self.structs[text(d)] = st
        self.done_ins = set()      # [[insert]] entries already placed in this program
        self.breaks = []           # the label of a break: of the innermost loop, None in a switch
        self.loops = 0             # the loops so far, for their break labels
        self.struct_types = {}
        for s in cfg.t.get('structs', []):
            if s not in self.structs:
                raise TransError('struct %s not found' % s)
            self.struct_types[s] = 'struct ' + pascal(s)

    # ---- types
    def c_type(self, key, ctype, ptr):
        t = self.cfg.get(self.cfg.types, key)
        if t is not None:
            return t
        if ptr:
            if ctype in ('void', 'char'):
                return ctype + ' *'
            if ctype in self.struct_types:
                return '(%s) *' % self.struct_types[ctype]
            if self.cfg.ctypes.get(ctype) in ('int', 'char'):
                return self.cfg.ctypes[ctype] + ' *'
        elif ctype in self.struct_types:
            return self.struct_types[ctype]
        if ctype in self.cfg.ctypes and not ptr:
            return self.cfg.ctypes[ctype]
        raise TransError('%s: no model type for C type %s%s; add it to [types]'
                         % (key, ctype, ' *' if ptr else ''))

    # ---- program
    def selected(self):
        roots = self.cfg.t.get('functions', []) + ([self.cfg.entry] if self.cfg.entry else [])
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
        src_order = [n for n in self.funcs if n in seen and n != self.cfg.entry]
        return src_order + ([self.cfg.entry] if self.cfg.entry else [])

    def program(self):
        out = []
        for s in self.cfg.t.get('structs', []):
            out += self.struct(s) + ['']
        if self.cfg.globals:
            out += self.global_vars() + ['']
        for name in self.selected():
            f = self.funcs[name]
            bad = [n for n in walk(f.node) if n.type == 'ERROR' or n.is_missing]
            if bad:
                raise TransError('%s: C parse error at line %d' % (name, bad[0].start_point[0] + 1))
            out += self.function(f) + ['']
        return out

    def global_cells(self):
        """The globals as the entry point loads and stores them: an array is its elements."""
        cells = []
        for g in self.cfg.globals:
            _, size = self.global_shape(g)
            cells += [camel(g)] if size is None else ['%s[# %d]' % (camel(g), k) for k in range(size)]
        return cells

    def global_shape(self, g):
        """(model type, array size or None) of the global g."""
        if g not in self.decls:
            raise TransError('global %s not found' % g)
        n, d = self.decls[g]
        _, ptr, arr = declarator_name(d)
        if ptr:
            raise TransError('global %s: a pointer is not kept (see the instance memory)' % g)
        t = self.c_type('global.%s' % g, base_type(n), False)
        if not arr:
            return t, None
        while d.type != 'array_declarator':
            d = d.child_by_field_name('declarator')
        size = text(d.child_by_field_name('size'))
        size = self.defines.get(size, size)
        if not re.fullmatch(r'\d+', str(size)):
            raise TransError('global %s: array size %s is not a number' % (g, size))
        return t, int(size)

    def global_vars(self):
        decls, inits = [], []
        for g in self.cfg.globals:
            t, size = self.global_shape(g)
            zeros = {'int': '# 0', 'bool': '# false', 'char': '# noData',
                     'TEE-OperationHandle': '# null', 'TEE-ObjectHandle': '# null'}
            if t not in zeros:
                raise TransError('global %s: type %s is not a base type or a handle' % (g, t))
            zero = zeros[t]
            if size is not None:
                decls.append('%s[%s] %s ;' % (t, size, camel(g)))
                inits += ['%s[# %d] := %s ;' % (camel(g), k, zero) for k in range(size)]
            else:
                decls.append('%s %s ;' % (t, camel(g)))
                inits.append('%s := %s ;' % (camel(g), zero))
        return decls + inits

    def struct(self, name):
        body = self.structs[name].child_by_field_name('body')
        lines = ['%s {' % self.struct_types[name]]
        for fd in named(body):
            if fd.type != 'field_declaration':
                continue
            fname, ptr, _ = declarator_name(fd.child_by_field_name('declarator'))
            lines.append(IND + '%s %s ;' % (self.c_type('%s.%s' % (name, fname), base_type(fd), ptr),
                                            camel(fname)))
        return lines + ['} ;']

    def function(self, f):
        self.f = f
        self.locals = {}            # C name -> C type
        drops = self.cfg.drop_args.get(f.name, set())
        if drops:
            self.cfg.used.add((id(self.cfg.drop_args), f.name))
        mem = self.cfg.memref.get(f.name)
        self.is_entry = f.name == self.cfg.entry
        if self.is_entry and mem is None:
            raise TransError('%s: the entry point needs a [memref.%s] table (its signature)' % (f.name, f.name))
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
                ps.append('%s %s' % (self.c_type('%s.%s' % (f.name, n), ct, ptr), camel(n)))
            sig = ', '.join(ps)
        if self.is_entry:
            sig += ', TEE-Result & ret'
        self.mallocs = set()
        self.ops = {}               # TEEC_Operation variable -> {index: model argument}
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
        # a void function ends with return unit; (fQuit in lang/c/semantics.maude pops a frame only on a
        # return), unless its body already ends with a return
        if f.ret == 'void' and not f.ret_ptr and not (body and body[-1].strip().startswith('return ')):
            body += [IND + 'return unit ;']
        if self.is_entry and self.cfg.globals:
            body = [IND + 'loadGlobals(%s) ;' % ', '.join(self.global_cells())] + body
        # result variables: next to res when it is declared, else first
        decls = [IND + '%s %s ;' % (self.c_type('%s.%s' % (f.name, n), t, False), camel(n))
                 for n, t in self.result_vars]
        if decls:
            at = next((k + 1 for k, ln in enumerate(body) if re.match(r'^\s*TEE-Result res ;$', ln)), 0)
            body[at:at] = decls
        if self.is_entry:
            head = 'void main (%s)' % sig
        else:
            head = '%s %s (%s)' % (self.c_type('%s.return' % f.name, f.ret, False), camel(f.name), sig)
        # an empty block of the model is { skip }
        filled = []
        for k, ln in enumerate(body):
            filled.append(ln)
            if ln.endswith('{') and k + 1 < len(body) and body[k + 1].strip() in ('}', '} else {'):
                filled.append(ln[:len(ln) - len(ln.lstrip())] + IND + 'skip')
        return [head, '{'] + filled + ['}']

    # ---- statements
    def block(self, node, depth):
        out = []
        items = named(node) if node.type == 'compound_statement' else [node]
        for s in items:
            out += self.stmt(s, depth)
        return out

    def gone(self, lines):
        """True when the output lines mention a variable of drop-vars (the statement is left
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
            if e.type == 'update_expression':
                return [pad + self.update(e)]
            raise TransError('%s: unsupported statement %s' % (self.f.name, text(s)[:60]))
        if t == 'if_statement':
            cond = s.child_by_field_name('condition')
            if self.malloc_check(cond):
                return []
            if any(n.type == 'identifier' and text(n) in self.dropped for n in walk(cond)):
                self.mixed_condition(cond)
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
            self.breaks.append(None)
            try:
                return self.switch(s, depth)
            finally:
                self.breaks.pop()
        if t in ('for_statement', 'while_statement'):
            return self.loop(s, depth)
        if t == 'return_statement':
            e = named(s)
            if not e and self.is_entry:
                raise TransError('%s: the entry point returns no value' % self.f.name)
            if not e:
                # a return of a void function is return unit; (fQuit in lang/c/semantics.maude)
                return [pad + 'return unit ;']
            e = e[0]
            if self.malloc_ptr(e) is not None:
                raise TransError('%s: returns the TEE_Malloc pointer %s; the model allocates it in '
                                 'the frame of the function' % (self.f.name, text(e)))
            if self.gone([self.expr(e)]):
                return []
            if self.is_entry:
                return [pad + 'ret := %s ;' % self.expr(e)] + self.entry_exit(depth)
            if self.contains_call(e):
                var = self.result_var_for(e, declare_here=True)
                out = []
                if var[1]:
                    out.append(pad + '%s %s ;' % (self.c_type('%s.%s' % (self.f.name, var[0]), var[2], False),
                                                 camel(var[0])))
                return out + [pad + '%s := %s ;' % (camel(var[0]), self.expr(e)), pad + 'return %s ;' % camel(var[0])]
            return [pad + 'return %s ;' % self.expr(e)]
        if t == 'goto_statement':
            return [pad + 'goto %s ;' % camel(text(named(s)[0]))]
        if t == 'labeled_statement':
            lab = camel(text(s.child_by_field_name('label')))
            return [pad + '%s :' % lab] + self.stmt(named(s)[-1], depth + 1)
        if t == 'compound_statement':
            return self.block(s, depth)
        if t == 'break_statement':
            if self.breaks and self.breaks[-1] is not None:
                return [pad + 'goto %s ;' % self.breaks[-1]]
            return []
        raise TransError('%s: unsupported statement %s: %s' % (self.f.name, t, text(s)[:60]))

    def entry_exit(self, depth):
        """The end of the entry point at a return: the globals are stored, and main returns."""
        pad = IND * depth
        out = [pad + 'storeGlobals(%s) ;' % ', '.join(self.global_cells())] if self.cfg.globals else []
        return out + [pad + 'return unit ;']

    def update(self, e):
        """x++, ++x, x-- or --x as a statement: x := x + 1 (or - 1)."""
        op = text(e.child_by_field_name('operator'))
        x = self.expr(e.child_by_field_name('argument'))
        return '%s := %s %s # 1 ;' % (x, x, '+' if op == '++' else '-')

    def loop(self, s, depth):
        """for (init; cond; update) body is init, then while (cond) { body update }; while (cond) body
        is the model's while.  A break in the body is a goto to a label after the loop (brkN), so
        the loop must be in a statement sequence that holds labels (the top level of a function
        body).  continue is not supported."""
        pad = IND * depth
        if any(n.type == 'continue_statement' for n in walk(s.child_by_field_name('body'))):
            raise TransError('%s: continue in a loop is not supported' % self.f.name)
        self.loops += 1
        label = 'brk%d' % self.loops
        out, step = [], []
        if s.type == 'for_statement':
            init = s.child_by_field_name('initializer')
            if init is not None:
                out += self.stmt(init, depth) if init.type == 'declaration' else \
                    self.stmt_of_expr(init, depth)
            upd = s.child_by_field_name('update')
            if upd is not None:
                step = self.stmt_of_expr(upd, depth + 1)
        cond = s.child_by_field_name('condition')
        c = '# true' if cond is None else self.expr(strip_parens(cond))
        if cond is not None and self.contains_call(cond):
            raise TransError('%s: a call in a loop condition is not supported' % self.f.name)
        self.breaks.append(label)
        try:
            body = self.block(s.child_by_field_name('body'), depth + 1)
        finally:
            self.breaks.pop()
        out += [pad + 'while (%s) {' % c] + body + step + [pad + '}']
        if any(ln.strip() == 'goto %s ;' % label for ln in body):
            self.labels_used = True
            out += [pad + '%s :' % label, pad + IND + 'skip']
        return out

    def stmt_of_expr(self, e, depth):
        pad = IND * depth
        if e.type == 'update_expression':
            return [pad + self.update(e)]
        if e.type == 'assignment_expression':
            return self.assignment(e, depth)
        raise TransError('%s: unsupported loop expression %s' % (self.f.name, text(e)[:60]))

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
                out.append(IND * depth + ins['c'])
        return out

    def declaration(self, s, depth):
        out = []
        for d in s.children_by_field_name('declarator'):
            name, ptr, arr = declarator_name(d)
            if name in self.dropped or name in self.inlines:
                continue
            if arr:
                raise TransError('%s: array %s; list it in drop-vars' % (self.f.name, name))
            ct = base_type(s)
            if ct == TEEC_OPERATION and not ptr:
                if d.type == 'init_declarator':
                    raise TransError('%s: the operation %s has an initializer' % (self.f.name, name))
                self.ops[name] = {}
                continue
            out.append(IND * depth + '%s %s ;' % (self.c_type('%s.%s' % (self.f.name, name), ct, ptr), camel(name)))
            if d.type == 'init_declarator':
                v = d.child_by_field_name('value')
                if self.malloc_ptr(v) is not None:
                    self.mallocs.add(name)
                init = self.assign_value(name, v, depth)
                if self.gone(init):
                    raise TransError('%s: the initializer of %s mentions a dropped variable' % (self.f.name, name))
                out += init
        return out

    def assignment(self, e, depth):
        lhs, rhs = e.child_by_field_name('left'), e.child_by_field_name('right')
        if e.child_by_field_name('operator') is not None and text(e.child_by_field_name('operator')) != '=':
            raise TransError('%s: compound assignment %s' % (self.f.name, text(e)))
        if lhs.type == 'identifier' and text(lhs) in self.inlines:
            return []
        if self.op_field(lhs, rhs):
            return []
        src = self.malloc_ptr(rhs)
        if src is not None:
            if lhs.type != 'identifier':
                raise TransError('%s: %s stores the TEE_Malloc pointer %s outside the function; the '
                                 'model allocates it in the frame of the function' % (self.f.name, text(e), src))
            self.mallocs.add(text(lhs))
        out = self.assign_value(lhs, rhs, depth)
        if self.gone(out):
            return []
        return (self.inserts(self.call_name(rhs), depth) if self.call_name(rhs) else []) + out

    def op_field(self, lhs, rhs):
        """True for an assignment to a field of a TEEC_Operation variable: a memory reference
        op.params[i].tmpref.buffer = X is collected for the call, and paramTypes and the sizes
        are left out."""
        m = re.match(r'^(\w+)\.(.*)$', norm(text(lhs)))
        if not m or m.group(1) not in self.ops:
            return False
        op, field = m.group(1), m.group(2)
        b = re.match(r'^params\[(\d+)\]\.tmpref\.buffer$', field)
        if b:
            k = int(b.group(1))
            if k in self.ops[op]:
                raise TransError('%s: %s is set twice' % (self.f.name, text(lhs)))
            self.ops[op][k] = self.expr(rhs)
        elif field != 'paramTypes' and not re.match(r'^params\[\d+\]\.tmpref\.size$', field):
            raise TransError('%s: the operation field %s is not modeled (only the buffers of '
                             'temporary memory references are)' % (self.f.name, text(lhs)))
        return True

    def invoke(self, args, sub):
        """teecInvokeCommand for TEEC_InvokeCommand(&sess, CMD, &op, &origin)."""
        inv = self.cfg.invoke
        if inv is None:
            raise TransError('%s: %s needs the [invoke] table' % (self.f.name, TEEC_INVOKE))
        self.cfg.used.add(('invoke',))
        if len(args) != 4:
            raise TransError('%s: %s takes 4 arguments, not %d' % (self.f.name, TEEC_INVOKE, len(args)))
        op = norm(text(args[2]))
        op = op[1:] if op.startswith('&') else op
        if op not in self.ops:
            raise TransError('%s: %s of %s is not a TEEC_Operation variable' % (self.f.name, text(args[2]), TEEC_INVOKE))
        bufs = self.ops[op]
        if sorted(bufs) != list(range(len(bufs))):
            raise TransError('%s: the memory references of %s are not params[0..n-1]' % (self.f.name, op))
        out = [self.expr(args[1], sub)] + [bufs[k] for k in sorted(bufs)]
        out.append('addr(%s)' % camel(inv['ta-result']))
        return 'teecInvokeCommand(%s, # %s, (%s))' % (self.api_arg(args[0], sub), inv['entry'], ', '.join(out))

    def assign_value(self, lhs, rhs, depth):
        name = lhs if isinstance(lhs, str) else None
        target = camel(lhs) if name else self.expr(lhs)
        if self.call_name(rhs) == 'TEE_Malloc':
            if not (name or lhs.type == 'identifier'):
                raise TransError('%s: the TEE_Malloc pointer is stored in %s, outside the function'
                                 % (self.f.name, text(lhs)))
            var = name or text(lhs)
            self.mallocs.add(var)
            call = rhs
            while call.type in ('cast_expression', 'parenthesized_expression'):
                call = call.child_by_field_name('value') if call.type == 'cast_expression' else named(call)[0]
            margs = named(call.child_by_field_name('arguments'))
            if len(margs) != 2 or norm(text(margs[1])) not in ('0', 'TEE_MALLOC_FILL_ZERO'):
                raise TransError('%s: TEE_Malloc with the hint %s; only TEE_MALLOC_FILL_ZERO (0) is '
                                 'modeled' % (self.f.name, text(margs[1]) if len(margs) > 1 else '?'))
            v = self.cfg.get(self.cfg.malloc, '%s.%s' % (self.f.name, var))
            return [IND * depth + '%s := malloc(%s) ;' % (target, v or '# zeroData')]
        return [IND * depth + '%s := %s ;' % (target, self.expr(rhs))]

    def malloc_ptr(self, e):
        """The TEE_Malloc pointer variable that the expression e is (through casts and
        parentheses), or None."""
        while e is not None and e.type in ('cast_expression', 'parenthesized_expression'):
            e = e.child_by_field_name('value') if e.type == 'cast_expression' else named(e)[0]
        if e is not None and e.type == 'identifier' and text(e) in self.mallocs:
            return text(e)
        return None

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
        if callee == TEEC_INVOKE:
            return 'TEEC_Result'
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
            if n == 'NULL':
                return 'nullptr'
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
            return 'nullptr'
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
            op = text(e.child_by_field_name('operator'))
            return '%s(%s)' % ('addr' if op == '&' else 'deref', self.expr(e.child_by_field_name('argument'), sub))
        if t == 'field_expression':
            op = text(e.child_by_field_name('operator'))
            return '%s %s %s' % (self.expr(e.child_by_field_name('argument'), sub),
                                 '->' if op == '->' else '.', camel(text(e.child_by_field_name('field'))))
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
            # the model has <= and == only, and no %: a < b is ! (b <= a), a > b is ! (a <= b),
            # a >= b is b <= a, and a % b is a - (a / b) * b (the model's / is the C quotient)
            if op == '<':
                return '! (%s <= %s)' % (self.expr(r, sub), self.expr(l, sub))
            if op == '>':
                return '! (%s <= %s)' % (self.expr(l, sub), self.expr(r, sub))
            if op == '>=':
                return '%s <= %s' % (self.expr(r, sub), self.expr(l, sub))
            if op == '%':
                a, b = self.expr(l, sub), self.expr(r, sub)
                return '(%s - (%s / %s) * %s)' % (a, a, b, b)
            if op in ('<<', '>>', '&', '^'):
                raise TransError('%s: operator %s is not in the model (change it in a patch)' % (self.f.name, op))
            return '%s %s %s' % (self.expr(l, sub), op, self.expr(r, sub))
        if t == 'call_expression':
            return self.call(e, sub)
        if t == 'subscript_expression':
            return '%s[%s]' % (self.expr(e.child_by_field_name('argument'), sub),
                               self.expr(e.child_by_field_name('index'), sub))
        raise TransError('%s: unsupported expression %s: %s' % (self.f.name, t, text(e)[:60]))

    def api_arg(self, e, sub):
        """An argument of a TEE API call: the stubs take an output argument by reference, so &x is
        the lvalue x."""
        if e.type == 'pointer_expression' and text(e.child_by_field_name('operator')) == '&':
            return self.expr(e.child_by_field_name('argument'), sub)
        return self.expr(e, sub)

    def call(self, e, sub):
        callee = text(e.child_by_field_name('function'))
        args = named(e.child_by_field_name('arguments'))
        if callee == TEEC_INVOKE:
            return self.invoke(args, sub)
        if callee in API:
            name, arity, spec = API[callee]
            if len(args) != arity:
                raise TransError('%s: %s takes %d arguments, not %d' % (self.f.name, callee, arity, len(args)))
            out = []
            for a in spec:
                if isinstance(a, tuple) and a[0] == 'ptr':
                    out.append(self.expr(args[a[1]], sub))
                elif isinstance(a, tuple):
                    v = self.api_arg(args[a[0]], sub)
                    out.append('# %s(%s)' % (a[1], v[2:]) if v.startswith('# ') else v)
                else:
                    out.append(self.api_arg(args[a], sub))
            return '%s(%s)' % (name, ', '.join(out))
        if callee in self.funcs:
            drops = self.cfg.drop_args.get(callee, set())
            return '%s(%s)' % (camel(callee), ', '.join(self.expr(a, sub) for k, a in enumerate(args) if k not in drops))
        raise TransError('%s: call of %s, which is neither kept nor a TEE API function the '
                         'preprocessor knows; add it to drop-calls or to the API table'
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


def top_level(n):
    """The top-level items of a translation unit, looking through #if, #ifdef and #ifndef blocks
    (the include guards of headers)."""
    for c in n.children:
        if c.type in ('preproc_ifdef', 'preproc_if', 'preproc_else', 'preproc_elif'):
            yield from top_level(c)
        else:
            yield c


# ------------------------------------------------------------------------------------------ main

def apply_patches(src, patches):
    cur = ''
    for f in (src if isinstance(src, list) else [src]):
        with open(f, encoding='utf-8') as fh:
            cur += fh.read()
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


DECL_LINE = re.compile(r'^\s*(?!goto |return )(\S.*) (\w+) ;$')


def decls_of(bodies):
    """The declarations of the names of the programs (a template line ---@decls): the variables,
    struct members and parameters (Var), the functions (FuncId), the labels (Label) and the struct
    types (CType)."""
    var, fun, lab, typ = set(), set(), set(), set()
    for body in bodies:
        for ln in body.split('\n'):
            m = re.match(r'^\s*struct (\w+) \{$', ln)
            if m:
                typ.add(m.group(1))
                continue
            m = re.match(r'^\s*(?:\S.*?) (\w+) \((.*)\)$', ln)
            if m and ':=' not in ln and not ln.strip().startswith(('if', 'while')):
                fun.add(m.group(1))
                var.update(p.split()[-1] for p in m.group(2).split(',') if p.strip())
                continue
            m = re.match(r'^\s*(\w+) :$', ln)
            if m:
                lab.add(m.group(1))
                continue
            for g in re.findall(r'goto (\w+) ;', ln):
                lab.add(g)
            m = DECL_LINE.match(ln)
            if m and ':=' not in ln and '(' not in m.group(1).replace('(struct', ''):
                var.add(m.group(2))
    out = []
    for names, sort in ((var, 'Var'), (fun, 'FuncId'), (lab, 'Label'), (typ, 'CType')):
        names = sorted(names)
        for k in range(0, len(names), 8):
            out.append('  ops %s : -> %s [ctor] .' % (' '.join(names[k:k + 8]), sort))
    return out


def translate(manifest, key, out_path=None, section='ta'):
    with open(manifest, 'rb') as fh:
        data = tomllib.load(fh)
    base = os.path.dirname(os.path.abspath(manifest))
    table = data[section][key]
    cfg = Config(table, base)
    if ('entry' in table) == ('main' in table):
        raise TransError('[%s.%s]: give one of entry and main' % (section, key))
    main = []
    if 'main' in table:
        with open(cfg.path(table['main']), encoding='utf-8') as fh:
            main = fh.read().rstrip('\n').split('\n')
    bodies = {}
    for prog, extra in table['programs'].items():
        srcs = table['source'] if isinstance(table['source'], list) else [table['source']]
        src = apply_patches([cfg.path(f) for f in srcs], [cfg.path(p) for p in table.get('patches', []) + extra])
        tr = Translator(cfg, src)
        lines = tr.program() + main
        bodies[prog] = '\n'.join(('    ' + ln) if ln else '' for ln in lines)
    unused = []
    for name, tab in (('types', cfg.types), ('drop-args', cfg.drop_args),
                      ('malloc', cfg.malloc), ('inline', cfg.inline), ('rewrite', cfg.rewrite),
                      ('assign', cfg.assign)):
        unused += ['[%s] %s' % (name, k) for k in tab if (id(tab), k) not in cfg.used]
    unused += ['drop-vars %s' % k for k in cfg.drop_vars if (id(cfg.drop_vars), k) not in cfg.used]
    unused += ['drop-calls %s' % k for k in cfg.drop_calls if ('call', k) not in cfg.used]
    unused += ['[[insert]] %d' % k for k in range(len(cfg.insert)) if ('ins', k) not in cfg.used]
    if cfg.invoke is not None and ('invoke',) not in cfg.used:
        unused.append('[invoke]')
    for fn, mem in cfg.memref.items():
        unused += ['[memref.%s] %s' % (fn, k) for k in mem if k != 'signature' and ('mem', fn, norm(k)) not in cfg.used]
    if unused:
        raise TransError('manifest entries that match nothing: ' + '; '.join(sorted(unused)))
    with open(cfg.path(table['template']), encoding='utf-8') as fh:
        tmpl = fh.read()
    if any(ln.strip() == '---@decls' for ln in tmpl.split('\n')):
        tmpl = '\n'.join('\n'.join(decls_of(bodies.values())) if ln.strip() == '---@decls' else ln
                         for ln in tmpl.split('\n'))
    for prog, body in bodies.items():
        marker = '---@program %s' % prog
        lines = tmpl.split('\n')
        at = [k for k, ln in enumerate(lines) if ln.strip() == marker]
        if len(at) != 1:
            raise TransError('template: expected one line %s' % marker)
        lines[at[0]] = '  eq %s =\n\n%s\n  .' % (prog, body)
        tmpl = '\n'.join(lines)
    out_path = out_path or os.path.join(base, table.get('output', key + '.maude'))
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, 'w', encoding='utf-8') as fh:
        fh.write(tmpl)
    return out_path


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('manifest')
    ap.add_argument('--ta', help='key of the [ta.KEY] table')
    ap.add_argument('--ra', help='key of the [ra.KEY] table')
    ap.add_argument('--out', help='output file (only with one TA or RA); default: its output entry')
    args = ap.parse_args(argv)
    with open(args.manifest, 'rb') as fh:
        data = tomllib.load(fh)
    if args.ta or args.ra:
        keys = [('ta', args.ta)] if args.ta else [('ra', args.ra)]
    else:       # every TA and every RA
        keys = [(sec, k) for sec in ('ta', 'ra') for k in data.get(sec, {})]
    try:
        for sec, k in keys:
            print('preprocess: %s' % translate(args.manifest, k, args.out, sec))
    except TransError as ex:
        sys.stderr.write('preprocess: error: %s\n' % ex)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
