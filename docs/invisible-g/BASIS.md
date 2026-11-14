# Basis of the remaining differences, current spec vs artifact (2026-11-13)

Setting: NON, unpatched, both with the artifact G selection (README.md).  Steps of one TA call:
current 358, artifact 410; RA steps per request: current 33, artifact 79.

References:
- FAC = the FAC 2026 paper (/tmp/mp/fac-paper.txt, line numbers of the text dump).
- K2013 = Rosu, Serbanuta, "K Overview and SIMPLE Case Study", 2013
  (formal-systems-laboratory.github.io/fsl/papers/2013/rosu-serbanuta-2013-k/; text dump
  /tmp/mp/kpaper/k2013.txt).
- C11 = ISO/IEC 9899:2011 (clauses cited from memory or from commit messages; not checked
  against the standard text here).

| # | difference (steps per TA call) | current | artifact | basis of the current spec | basis of the artifact |
|---|---|---|---|---|---|
| 1 | declarations: 0 vs 108 | var and struct declarations are allocated by equations at block entry (hoistK, alloc eqs), since d070b43 (2026-10-17, "Hoist declarations to block entry ... (C11 6.2.4p6)", "Make deterministic steps equations") | `var X`, `$structNameDecl`, `$structMemDecl`, `$clearMem` are rules, not in its G | C11 6.2.4p6 for the time of allocation (block entry).  None for making it an equation: K2013 3.4 gives the SIMPLE `var X ;` rule without the structural tag, and K2013 2.4 (l. 360-366) says untagged rules are computational, i.e. observable steps.  FAC 2.3.2 (l. 385-386) also has alloc as "a separate rule"; only FAC 8.1 G2 (all K rules except loops and calls) would hide it, together with lookup and assign | K2013 (declaration = computational step), FAC 2.3.2 (alloc is a rule) |
| 2 | API argument binding: 60 vs 0 | tee-api-call gives `zip ~> invoke(stub)`, and the arguments are bound by fExec/bindV/bindR | `TEEAPI(EL)` and `$callByValArg` are equations; no binding | FAC D.2 (l. 2530-2531): after the arguments are evaluated, "(the Maude versions of) fExec, bindV, and bindR rules are applied, resulting in the subsequent task $in(in)"; FAC 6.2 tee-api-call (l. 1282) with `zip(PL, EL)` | none found in FAC |
| 3 | parameters of program functions: 26 vs 2 | call by value (bindV: alloc, then assign), by reference only for `&`/pointer parameters (bindR) | `$callByRefArg`: a variable argument is bound by reference (alias, an equation); only a non-location value is allocated (`$callByRefInst(V, X)`, a rule) | FAC 2.3.2 Fig. 4 and l. 372-386 (bindV for call by value with alloc and assignment, bindR for `&x`); C11 6.5.2.2p4 (each parameter is assigned the value of its argument) | none found in FAC or C11 |
| 4 | storage service: 8 vs 20 | a Storage object answers getStatus/checkFileExist in one rule (return-storage-status, return-file-exist) | TeeOSKernel service: service-receive, get-storage-status or check-file-exist, service-finish | FAC 3.2 (l. 590-612: class Storage, `msg getStatus[] from O to SI`) and FAC 5 rule return-storage-status (l. 2138) | none found in FAC |

RA side (33 vs 79 steps per request): declarations 0 vs 15 (#1), the SMC protocol 8 vs 10, reads
8 vs 28 and writes 17 vs 25.  Write-back after the call: current 2 writes (the output
parameters), artifact 13 (`$out(EL' | EL)` for a TEE Client API call writes back the inputs as
well).  FAC D.2 (l. 2557-2558): the RA "completes the invocation by assigning the return values to the
output parameter".  The remaining read difference (TA 164 vs 182, RA 8 vs 28) is not attributed
yet.

Summary: #2, #3, #4 follow FAC where the artifact does not.  #1 is a choice of the current spec
(commit d070b43) with no basis in K2013 or FAC 2.3.2; K2013 supports the artifact.

ER2012 = Ellison, Rosu, "An Executable Formal Semantics of C with Applications", POPL 2012
(fsl.cs.illinois.edu/publications/ellison-rosu-2012-popl.pdf; text /tmp/mp/er2012/q.txt).  The
README of d070b43 said imp.maude is "in the style of" ER2012 "with these choices", one choice
being "Local, deterministic, terminating steps (... declarations ...) are equations" (README
removed in 953428d).  ER2012 does not make that choice: it does not separate structural from
computational rules or rules from equations for its steps; it counts all of them as "1,163
semantic rules" (l. 77-83) and describes allocation as rules (malloc/alloc, l. 960-975).  Its
state-space reduction is semantic (side effects applied immediately, l. 1145-1163), not hiding
deterministic steps.  So the choice was the spec's own; ER2012 does not support it.  The K-Maude
source of ER2012 (structural tags) was not checked.

## Change for #1 (2026-11-13)

imp.maude: allocA, alloc and allocObj are rules (were equations), as FAC 2.3.2 has alloc as a
rule.  They are not in G (decisions.tsv: the artifact keeps var X, $structNameDecl and
$structMemDecl as rules).  The other declaration equations (decl, sDecl, sMemDecl, setStruct,
reset-*, assn-*) stay equations.

NON, unpatched, G on: P1 states 28,870 -> 42,010 (artifact 36,024).  Steps of one TA call:
358 -> 524 (+ alloc 161, allocObj 5): 80 for declarations, 86 for parameter binding (26 program
functions, 60 API stubs; FAC Fig. 4 bindV = alloc, then assign).  RA steps per request: 33 -> 47.

Spec tests (tests/run-checks.py, tests/run-api-suite.py): the allocation change alone breaks no
check (same results with the equations restored, /tmp/mp/base-tree).  invisible.maude lines 24
and 37 fail with the new G and pass with the old one: they expect isAlgorithmSupported (start)
and cipherDoFinal (finish) to be invisible, and these API functions have no artifact G rules.
data-stream.maude 5/9, generic.maude 5/6, internal-client.maude 8/13, shared-memory.maude 3/25
fail with the old G and the allocation equations as well, so they come from earlier
uncommitted changes; not investigated.  All other files pass; API suite 96/96.

## Why the current spec now has more states (42,010 vs 36,024)

Steps of one TA call, current 524 vs artifact 410 (+114):

| step | current | artifact | difference | basis of the current spec |
|---|---|---|---|---|
| parameter binding of API stubs (alloc + assign) | 120 (60 + 60) | 0 | +120 | FAC D.2 (l. 2530-2531): after the arguments of a TEE API call are evaluated, fExec, bindV and bindR are applied; FAC 2.3.2 Fig. 4: bindV = alloc(x) then x := v; alloc is a rule (l. 385-386), assign is a rule (Fig. 3) |
| parameter binding of program functions (alloc + assign) | 52 (26 + 26) | 2 | +50 | FAC 2.3.2 Fig. 4 (value parameters by bindV, `&x` by bindR); FAC D.3 (l. 2593-2602): the service runs as mkConf(P, f, vl) = ... callFunc(f, vl), an ordinary call of f, so the 12 parameters of main are bound by bindV; C11 6.5.2.2p4 |
| declarations | 80 | 108 | -28 | FAC 2.3.2 (alloc is a rule) |
| memory reads | 164 | 182 | -18 | not attributed |
| memory writes of statements and output write-back | 99 | 97 | +2 | |
| storage service | 8 | 20 | -12 | FAC 3.2 (Storage object, one rule per request) |
| end of call | 1 | 1 | 0 | |

All of the excess is parameter binding (+170).  The artifact has no such steps: its TEE API
arguments are handled by equations ($callByValArg) and a variable argument of a program
function is bound by reference ($callByRefInst(loc(L), X), an equation); only a value argument
takes a rule step ($callByRefInst(V, X)).  No basis for this was found in FAC.

The excess comes from combining the FAC call semantics with the artifact G.  In FAC 8.1, G2 is
all K rules except loops and function calls, so alloc, assign and lookup are invisible and a
binding costs no visible step (bindV and fExec, being function-call rules, stay visible).  The
artifact G keeps memory reads and writes visible, so with the FAC call semantics each value
parameter costs two visible steps (alloc, assign).

## Test fixes (2026-11-13)

- invisible.maude: the G1 checks use CipherUpdate (cipher-update-req-cipher, cipher-update-success),
  which has artifact G rules; a check that the IsAlgorithmSupported start state is a state added.
- internal-client, shared-memory, data-stream: TrustedApp objects written in full get
  `running : false` (`true` when proc runs a program), and the duplicated `state-changed` is
  removed (running was restored in 6cca5ff; the tests were not updated).
- data-stream, generic: an init-stage panic leaves `api-call : noCall` (the panic rules were
  changed so; the expected states still had init(...)).
- shared-memory 147, 151, 193: a TA that panics before accepting an API call has
  `state-changed : true` (set by handle-invoke-ta).
- Result: every checks file passes except internal-client.maude line 129; API suite 96/96.
  Line 129 is a spec bug: c41ba12 removed `< RI : RichApp | >` from return-smc-request-panic,
  so a panicking TA serving another TA (client-service {testTa, main}) also sends smcRet to the
  calling TA, besides the session answer of handle-session-req-panic.
- Fix of line 129: a session request of a TA is recorded as `sess{TK, FUNC}` (new constructor in
  CLIENT-SERVICE, tee-app.maude; session.maude uses it in its three rules); `{RI, FID}` (FAC D.3)
  is recorded only by handle-invoke-ta, so return-smc-request-panic matches RA requests only,
  with no location condition (an RA in `{REE}` still matches).  internal-client 121, 133 use
  `sess{testTa, main}`.  All completion checks pass (13/13 in internal-client), API suite 96/96,
  P1 NON states unchanged (42,010).

## Why the state count follows the visible TEE-side steps (2026-11-13)

Graph decomposition (scripts an.py; NON, unpatched, artifact G):

| | old (alloc eqs) | current | artifact |
|---|---|---|---|
| states | 28,870 | 42,010 | 36,024 |
| TEE-side projections | 4,269 | 6,249 | 5,347 |
| states per TEE projection | 6.76 | 6.72 | 6.74 |
| distinct TA-only projections | 3,585 | 5,245 | 3,975 |
| distinct RA-only projections | 113 | 169 | 293 |

The histogram of states per TEE projection has the same shape in all three (3, 4, 6, 9, 10, 12
publisher states): the publisher interleaving is the same, so the number of states is about 6.7
times the number of distinct TEE-side states.  42,010 / 36,024 = 1.166 and 6,249 / 5,347 = 1.169.
TA-only +1,270 vs the artifact matches 11 distinct TA calls x 114 extra steps (1,254); RA-only
-124 matches fewer RA steps (47 vs 79 per request).  old -> current: +1,980 TEE projections, the
alloc steps (12,702 alloc + 438 allocObj arcs, about 6.6 arcs per step).

## IMP standardization (2026-11-13)

Basis order: FAC where it defines the language (a subset of C, l. 100-102, 1242-1249; Fig. 2-4,
D.2), otherwise C (FAC [18] = Ellison-Rosu POPL 2012; C11), the artifact where it agrees with C.

Changes in tee-formal-spec:
1. Nested structs: resetMembers and copyMembers recurse into struct members (C11 6.5.16.1p2,
   6.2.4p6).  A nested struct member was reset to undef, so any access was stuck.
2. A block may declare a name of an outer scope again (C11 6.2.1p4; SIMPLE Rho[X <- T]): new
   typing cell tscope (names of the current scope); a function body starts with its parameters.
3. auto removed (C11: a storage class; type inference is C23).  The 'ret of a TEE API stub is
   declared with the stub's return type.
4. float removed (no values, no use).
5. Reference parameters only as U & X (FAC &x, Fig. 4 and D.2); U * X removed.  shared-memory
   &_ gets prec 31 so that U & X has one parse.  Programs, stubs and tests use &.
6. The policy comment of IMP-SEMANTICS: K rules are rules, G decides visibility.
6-1. Equations with an artifact counterpart became labeled rules: member-lvalue, op-*, skip,
   seq (now at the top of the k cell only, as the artifact S ; S'), fdecl, fdecl-lib, sdecl,
   assign-list(-end).  In G (decisions.tsv) when the counterpart is in the artifact G; not in G:
   op-or-true/false (the artifact G has no || rule), op-minus (no artifact counterpart).

Results: all completion checks pass (imp-semantics 40/40, typing 60/60), API suite 96/96, P1 NON
42,010 states (unchanged).  The NON scenario RA (mqttzHost) has no ||; the patched RA has one,
so patched scenarios may change.

Not changed (no 1:1 artifact counterpart; would change state counts): member-read, elem-read and
the struct assignment are equations, while the artifact reads a member with two visible reads
(leval of the struct, leval of the member) and writes a struct with one visible loc := V.
Kept as equations (bookkeeping with no artifact rule): heating/cooling, goto/labels (equations in
the artifact), hoisting, $restoreEnv, $genv, decl/$setLoc, struct object layout, reset/assn, elem.
