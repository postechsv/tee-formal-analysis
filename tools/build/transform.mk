# The transforms of a spec build, run from the repository root with make -f tools/build/transform.mk
# (written M below).  tools/build/tee-build.py runs it to build an analysis of a case study (the
# Makefile of the case study: make A in C/).
#
# It transforms one build of a spec checkout SPEC (a tee-formal-spec tree; tee-build passes the one
# it fetched).  The spec is built with its own Makefile (make -C $(SPEC) NAME=t src, which takes the
# feature settings, e.g. CRYPTO=0, or a build configuration file CONFIG=x.toml) into
# $(SPEC)/build/t/, and the transforms are applied to a copy of it:
#
#   M SPEC=DIR NAME=t       build build/t/src and build/t/tests (a plain copy of the spec build)
#   M NAME=t DMC=1          build the DM-Check version (tools/dmc/gen-dmc.py) instead of a plain copy
#   M NAME=t DMC=1 DMC_DIRECTIVES=x.toml  with the directives of x.toml (a directives file, or an
#                           analysis .toml with a [dmc] table); required with DMC=1.
#                           Cached like DMC.
#   M NAME=t GHOST=x.maude  compose the ghost file(s) with the spec rules (tools/build/ghost.py)
#                           before the copy or gen-dmc; a space-separated list is allowed, and an
#                           analysis .toml gives its [ghost] tables. Cached like DMC; GHOST= turns it off.
#   M NAME=t DROP_RULES=x.toml  remove the rules of the drop-rules list of an analysis .toml
#                           (tools/build/drop-rules.py) first. Cached like GHOST.
#   M NAME=t DROP_ATTR=x.toml  drop the class attributes of the [drop-class-attribute] tables of
#                           an analysis .toml (tools/build/drop-class-attribute.py) from rule left-hand
#                           sides before the ghosts. Cached like GHOST.
#   M NAME=t INVISIBLE_G=x.toml  the invisible-transition reduction generated from the [invisible]
#                           rules of x.toml (tools/build/gen-invisible.py) into src/invisible-reduction.maude,
#                           which src/main.maude then loads last
#   M NAME=t test           build, then run the spec test suites on build/t/tests
#   M test-api, test-checks, V=1 test  as in the spec Makefile, on build/t
#   M dmc                   same as M DMC=1 (the setting is cached)
#   M check-dmc             regenerate the DMC build and run gen-dmc's ground checks (exit 2 on mismatch)
#   M NAME=t DMC=1 M2L=1    build the maude2lean version (tools/gen-maude2lean.py on the DMC build)
#   M m2l                   same as M DMC=1 M2L=1 (cached)
#   M check-m2l             regenerate the M2L build and run gen-maude2lean's checks
#   M lean                  translate the M2L build to Lean: build/t/lean/TeeSpec.lean (MAUDE2LEAN)
#   M help                  list settings and targets
#   M clean NAME=t          remove build/t
#
# build/ is a cache: build/spec/ holds the fetched spec revisions (and their own builds), build/NAME/
# a transformed build:
#   src/, tests/   the final tree: a copy of the spec build (DMC=0) or the gen-dmc output (DMC=1).
#                  Nothing else is written there by the DMC build.
#   lang/          the language files of a spec that has them next to src/ (src/main.maude loads
#                  ../lang/c/semantics): copied, or written by gen-dmc/gen-maude2lean at the same
#                  path relative to src/. Absent for a spec without lang/.
#   .dmc-cache/    DMC=1 bookkeeping (reflection cache, manifest.json, check-build). Kept across
#                  builds; only make clean removes it.
#   .m2l/dmc-src/  M2L=1: the gen-dmc output that gen-maude2lean reads (src/ is its output)
#   .m2l-cache/    M2L=1 bookkeeping (reflection cache, manifest.json, check inputs)
#   lean/          make lean output
#   config.mk, config.want, .stamp (build marker)
#   .stage/        intermediate, removed after each successful build. A failed build leaves
#                  the stamp untouched, so the next run rebuilds.
#
# Setting precedence: command line > build/$(NAME)/config.mk (cache) > defaults.  The feature
# settings are cached by the spec build ($(SPEC)/build/$(NAME)/config.mk).
# Personal settings such as the Maude path go in config.mk at the repo root (gitignored).

# This file, for the recursive runs (there is no Makefile at the repository root).
SELF := $(firstword $(MAKEFILE_LIST))

# Ignore a NAME inherited from the shell environment; only make arguments or config.mk set it.
ifneq ($(filter environment%,$(origin NAME)),)
NAME := default
endif
NAME ?= default
OUT := build/$(NAME)
STAGE := $(OUT)/.stage
FINAL_STAMP := $(OUT)/.stamp

# Personal settings (gitignored). Read before MAUDE so it can set MAUDE.
-include config.mk

# Maude binary. Set MAUDE in config.mk, or MAUDE_BIN in the environment.
MAUDE ?= $(or $(MAUDE_BIN),maude)
export MAUDE_BIN := $(MAUDE)

# maude2lean (make lean). Set MAUDE2LEAN in config.mk, e.g. the binary of a virtualenv.
MAUDE2LEAN ?= maude2lean
M2L_FLAGS ?= --lean-version 4
LEAN_OUT = $(OUT)/lean/TeeSpec.lean

# Settings used by the previous build in this directory.
-include $(OUT)/config.mk

# The spec checkout (a tee-formal-spec tree with its Makefile). Cached like DMC.
SPEC ?=
SPEC_OUT = $(SPEC)/build/$(NAME)

# DM-Check transform (tools/dmc/gen-dmc.py).
DMC ?= 0
# The directives of the DM-Check transform: a directives file, or an analysis .toml with a [dmc]
# table (e.g. kmgk/dmc.toml); required with DMC=1.
DMC_DIRECTIVES ?=

# maude2lean build (tools/gen-maude2lean.py): the DMC build without sort tests. Needs DMC=1;
# cached like DMC.
M2L ?= 0
# M2L_EQ=0: the M2L build without gen-dmc's _.=._ (gen-maude2lean --no-eq; its uses become the built-in ==).
M2L_EQ ?= 1

# Ghost files (tools/build/ghost.py) composed with the stage.
GHOST ?=
# Analysis .toml whose drop-rules list removes rules of the spec (tools/build/drop-rules.py).
DROP_RULES ?=
# Analysis .toml whose [drop-class-attribute] tables drop class attributes from rule left-hand
# sides (tools/build/drop-class-attribute.py).
DROP_ATTR ?=
# Analysis .toml whose [invisible] rules give the invisible-transition reduction.  The reduction is
# part of the analysis, not of the spec: src/invisible-reduction.maude is generated from the rules
# (tools/build/gen-invisible.py) after the ghosts are composed, so that an invisible step updates
# the ghost state like its rule, and a load of it is added at the end of src/main.maude.  Without
# it, there is no reduction.
INVISIBLE_G ?=

# Verbose output (V=1 or VERBOSE=1): the test runners stream Maude's output and the recipes
# are echoed. Display only, so it is not written to config.want or the cache, and changing it
# does not rebuild. Like NAME, an inherited environment value is ignored.
ifneq ($(filter environment%,$(origin V)),)
V := 0
endif
ifneq ($(filter environment%,$(origin VERBOSE)),)
VERBOSE := 0
endif
V ?= $(or $(VERBOSE),0)
Q = $(if $(filter 1,$(V)),,@)
VFLAG = $(if $(filter 1,$(V)),-v)

.PHONY: all src test test-api test-checks dmc check-dmc m2l check-m2l lean help config clean distclean FORCE

all: src

# The goals that build: everything but help/clean.
BUILD_GOALS := $(filter-out help config clean distclean,$(or $(MAKECMDGOALS),all))

# Stop early on invalid values or unmet requirements.
ifneq ($(BUILD_GOALS),)
$(if $(SPEC),,$(error SPEC is not set: give a tee-formal-spec checkout (SPEC=DIR), or build a case study (make in mqttz/)))
$(if $(wildcard $(SPEC)/Makefile),,$(error $(SPEC)/Makefile not found: SPEC must be a tee-formal-spec checkout))
endif
$(if $(filter-out 0 1,$(V)),$(error V must be 0 or 1, got '$(V)'))
$(if $(filter-out 0 1,$(DMC)),$(error DMC must be 0 or 1, got '$(DMC)'))
$(if $(filter-out 0 1,$(M2L)),$(error M2L must be 0 or 1, got '$(M2L)'))
$(if $(filter 1,$(M2L)),$(if $(filter 0,$(DMC)),$(error M2L=1 requires DMC=1)))
$(if $(filter-out 0 1,$(M2L_EQ)),$(error M2L_EQ must be 0 or 1, got '$(M2L_EQ)'))
$(foreach G,$(GHOST),$(if $(wildcard $(G)),,$(error GHOST file '$(G)' not found)))
$(if $(DROP_RULES),$(if $(wildcard $(DROP_RULES)),,$(error DROP_RULES file '$(DROP_RULES)' not found)))
$(if $(DROP_ATTR),$(if $(wildcard $(DROP_ATTR)),,$(error DROP_ATTR file '$(DROP_ATTR)' not found)))
$(if $(INVISIBLE_G),$(if $(wildcard $(INVISIBLE_G)),,$(error INVISIBLE_G file '$(INVISIBLE_G)' not found)))
$(if $(filter 1,$(DMC)),$(if $(strip $(DMC_DIRECTIVES)),,$(error DMC=1 needs DMC_DIRECTIVES: a directives file, or an analysis .toml with a [dmc] table)))
$(if $(filter 1,$(DMC)),$(if $(wildcard $(DMC_DIRECTIVES)),,$(error DMC_DIRECTIVES file '$(DMC_DIRECTIVES)' not found)))

# gen-dmc reads the stage and writes $(OUT)/src; derived tests go to $(OUT)/tests. Its
# bookkeeping lives in $(OUT)/.dmc-cache, outside src/ (the DMC=0 path replaces src/ wholesale).
# DMC_CHECK=1 (set by check-dmc) adds --check.
# With M2L=1, gen-dmc writes $(OUT)/.m2l/dmc-src and gen-maude2lean reads it and writes $(OUT)/src;
# the derived tests load ../src/main, so they run on the M2L build. M2L_CHECK=1 (check-m2l) adds --check.
DMC_OUT = $(if $(filter 1,$(M2L)),$(OUT)/.m2l/dmc-src,$(OUT)/src)
GEN_M2L = python3 tools/gen-maude2lean.py $(OUT)/.m2l/dmc-src $(OUT)/src --cache-dir $(OUT)/.m2l-cache --maude $(MAUDE) $(if $(M2L_CHECK),--check) $(if $(filter 0,$(M2L_EQ)),--no-eq)
GEN_DMC = python3 tools/dmc/gen-dmc.py $(STAGE)/src $(DMC_OUT) --tests $(STAGE)/tests --tests-out $(OUT)/tests --cache-dir $(OUT)/.dmc-cache --maude $(MAUDE) --directives $(DMC_DIRECTIVES) $(if $(DMC_CHECK),--check)

# The spec build. Its Makefile is run every time (it rebuilds only what changed and caches the
# feature settings); the command-line settings reach it through MAKEFLAGS.
$(SPEC_OUT)/.stamp: FORCE
	$(Q)$(MAKE) --no-print-directory -C $(SPEC) NAME=$(NAME) src

# Everything that decides the final tree. config.want changes with every setting.
FINAL_INPUTS := $(SPEC_OUT)/.stamp $(OUT)/config.want
FINAL_INPUTS += $(if $(filter 1,$(DMC)),tools/dmc/gen-dmc.py $(wildcard tools/dmc/lib/*) $(DMC_DIRECTIVES) $(wildcard tools/dmc/*.toml))
FINAL_INPUTS += $(if $(filter 1,$(M2L)),tools/gen-maude2lean.py)
FINAL_INPUTS += $(if $(strip $(GHOST)),$(GHOST) tools/build/ghost.py tools/dmc/gen-dmc.py)
FINAL_INPUTS += $(if $(strip $(DROP_RULES)),$(DROP_RULES) tools/build/drop-rules.py tools/dmc/gen-dmc.py)
FINAL_INPUTS += $(if $(strip $(DROP_ATTR)),$(DROP_ATTR) tools/build/drop-class-attribute.py tools/dmc/gen-dmc.py)
FINAL_INPUTS += $(if $(strip $(INVISIBLE_G)),tools/build/gen-invisible.py $(INVISIBLE_G))

# The cache is updated last, so a failed build never leaves bad settings behind.
src: $(FINAL_STAMP)
	@echo "config: NAME=$(NAME) SPEC=$(SPEC) DMC=$(DMC) DMC_DIRECTIVES=$(DMC_DIRECTIVES) M2L=$(M2L) M2L_EQ=$(M2L_EQ) DROP_RULES='$(DROP_RULES)' DROP_ATTR='$(DROP_ATTR)' GHOST='$(GHOST)' INVISIBLE_G='$(INVISIBLE_G)'"
	@cmp -s $(OUT)/config.want $(OUT)/config.mk || cp $(OUT)/config.want $(OUT)/config.mk

# Stage, then the final tree, then the stage is removed. A failure before the touch
# leaves the stamp old, so the next run rebuilds (and starts by removing the stage).
$(FINAL_STAMP): $(FINAL_INPUTS) | $(OUT)
	$(Q)rm -rf $(STAGE) $(OUT)/tests $(OUT)/lang
	$(Q)mkdir -p $(STAGE)
	$(Q)cp -R $(SPEC_OUT)/src $(SPEC_OUT)/tests $(STAGE)/
	$(Q)if [ -d $(SPEC_OUT)/lang ]; then cp -R $(SPEC_OUT)/lang $(STAGE)/; fi
	$(Q)$(if $(strip $(DROP_RULES)),python3 tools/build/drop-rules.py --spec-src $(SPEC) $(STAGE)/src $(DROP_RULES))
	$(Q)$(if $(strip $(DROP_ATTR)),python3 tools/build/drop-class-attribute.py --spec-src $(SPEC) $(STAGE)/src $(DROP_ATTR))
	$(Q)$(if $(strip $(GHOST)),python3 tools/build/ghost.py --spec-src $(SPEC) $(STAGE)/src $(GHOST))
	$(Q)$(if $(strip $(INVISIBLE_G)),python3 tools/build/gen-invisible.py --src $(STAGE)/src --spec-src $(SPEC) $(INVISIBLE_G) && \
		{ grep -qx 'load invisible-reduction' $(STAGE)/src/main.maude || echo 'load invisible-reduction' >> $(STAGE)/src/main.maude; })
	$(Q)if [ '$(DMC)' = 1 ]; then \
		rm -rf $(OUT)/src $(OUT)/.m2l && $(GEN_DMC) $(if $(filter 1,$(M2L)),&& $(GEN_M2L)); \
	else \
		rm -rf $(OUT)/src && cp -R $(STAGE)/src $(OUT)/src && cp -R $(STAGE)/tests $(OUT)/tests && \
		if [ -d $(STAGE)/lang ]; then cp -R $(STAGE)/lang $(OUT)/lang; fi; \
	fi
	$(Q)rm -rf $(STAGE)
	$(Q)touch $@

# Run both suites in $(OUT)/tests. Each runs even if the other fails; the exit status
# is nonzero if either fails.
test: src
	@status=0; \
	$(MAKE) --no-print-directory -f $(SELF) test-api || status=1; \
	$(MAKE) --no-print-directory -f $(SELF) test-checks || status=1; \
	exit $$status

# The selected test files are those of the spec build ($(SPEC_OUT)/tests.txt).

test-api: src
	@api=$$(sed -n 's|^api |$(OUT)/tests/|p' $(SPEC_OUT)/tests.txt); \
	if [ -z "$$api" ]; then echo '[test-suite] no API tests selected'; \
	elif grep -qx api-full $(SPEC_OUT)/tests.txt; then python3 $(OUT)/tests/run-api-suite.py $(VFLAG); \
	else python3 $(OUT)/tests/run-api-suite.py $(VFLAG) $$api; fi

test-checks: src
	@checks="$$(sed -n 's|^check |$(OUT)/tests/|p' $(SPEC_OUT)/tests.txt)"; \
	if [ -z "$$(echo $$checks)" ]; then echo '[checks] no check files selected'; \
	else python3 $(OUT)/tests/run-checks.py $(VFLAG) $$checks; fi

# The DMC build is a cached setting: DMC=1 stays until DMC=0 is given.
dmc:
	@$(MAKE) --no-print-directory -f $(SELF) DMC=1 src

# Always regenerates (-B), then runs the ground checks. gen-dmc exits 2 on a mismatch.
# Not with M2L=1: gen-dmc's load check reads the tests next to its output, which is .m2l/dmc-src there.
check-dmc:
	@if [ '$(M2L)' = 1 ]; then echo 'check-dmc: not with M2L=1 (use NAME= of a build with M2L=0)'; exit 1; fi
	@$(MAKE) --no-print-directory -f $(SELF) -B DMC=1 DMC_CHECK=1 src

# The M2L build is a cached setting too (M2L=1 stays until M2L=0 is given).
m2l:
	@$(MAKE) --no-print-directory -f $(SELF) DMC=1 M2L=1 src

# Always regenerates (-B), then runs gen-maude2lean's checks (exit 2 on a mismatch, 3 on load warnings).
check-m2l:
	@$(MAKE) --no-print-directory -f $(SELF) -B DMC=1 M2L=1 M2L_CHECK=1 src

# Lean translation of the M2L build (https://github.com/fadoss/maude2lean). Set MAUDE2LEAN in config.mk;
# M2L_FLAGS are passed to it (e.g. --module TEE-BEHAVIOR).
lean: src
	@if [ '$(M2L)' != 1 ]; then echo 'make lean needs the M2L build (M2L=1)'; exit 1; fi
	@mkdir -p $(OUT)/lean
	cd $(OUT)/src && $(MAUDE2LEAN) main.maude $(M2L_FLAGS) -o $(abspath $(LEAN_OUT))

help config:
	@echo "NAME=$(NAME)  OUT=$(OUT)  SPEC=$(SPEC)  MAUDE=$(MAUDE)"
	@echo "settings (features: make -C SPEC help):"
	@echo "  DMC=$(DMC)  DMC_DIRECTIVES=$(DMC_DIRECTIVES)"
	@echo "  M2L=$(M2L)  M2L_EQ=$(M2L_EQ)  (MAUDE2LEAN=$(MAUDE2LEAN))"
	@echo "  DROP_RULES=$(DROP_RULES)"
	@echo "  DROP_ATTR=$(DROP_ATTR)"
	@echo "  GHOST=$(GHOST)"
	@echo "  INVISIBLE_G=$(INVISIBLE_G)"
	@echo "  V=$(V)  (display only: not cached; V=1 streams test output)"
	@echo "targets (make -f tools/build/transform.mk ...):"
	@echo "  make [src]     build $(OUT)/src and $(OUT)/tests (DMC=1: gen-dmc output)"
	@echo "  make test      test-api and test-checks (V=1: stream each file's Maude output)"
	@echo "  make test-api  API-level tests (run-api-suite.py)"
	@echo "  make test-checks  search/red checks (run-checks.py)"
	@echo "  make dmc       same as DMC=1 (cached)"
	@echo "  make check-dmc regenerate the DMC build and run its ground checks"
	@echo "  make m2l       same as DMC=1 M2L=1 (cached): the maude2lean build"
	@echo "  make check-m2l regenerate the M2L build and run its checks"
	@echo "  make lean      translate the M2L build with maude2lean: $(LEAN_OUT)"
	@echo "  make clean     remove $(OUT)"
	@echo "  make distclean remove build/ (the fetched specs too)"

clean:
	rm -rf $(OUT)

distclean:
	rm -rf build

$(OUT):
	@mkdir -p $@

# Desired settings, rewritten only when they change. The final tree depends on it.
# Copied to the cache config.mk (read by the next run) after a successful build.
# Gated so help/clean never create build directories.
ifneq ($(BUILD_GOALS),)
$(OUT)/config.want: FORCE | $(OUT)
	@printf '%s\n' '# Generated by Makefile. Do not edit.' 'SPEC := $(SPEC)' 'DMC := $(DMC)' 'DMC_DIRECTIVES := $(DMC_DIRECTIVES)' 'M2L := $(M2L)' 'M2L_EQ := $(M2L_EQ)' 'DROP_RULES := $(DROP_RULES)' 'DROP_ATTR := $(DROP_ATTR)' 'GHOST := $(GHOST)' 'INVISIBLE_G := $(INVISIBLE_G)' > $@.tmp
	@if cmp -s $@.tmp $@; then rm -f $@.tmp; else mv $@.tmp $@; fi
endif

FORCE:
