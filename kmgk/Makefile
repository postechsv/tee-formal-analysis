# The analyses of KMGK: its analysis files, the *.toml files with a [spec] table (see README.md).
#
#   make model-checking     build model-checking.toml into its output directory
#                           (tools/build/tee-build.py): its spec, fetched into ../build/spec/, built
#                           and transformed with its settings, with core/ and the preprocessed TAs
#   make                    every analysis
#   make A SPEC=DIR         the analysis A on a spec checkout instead of the revision of A.toml
#   make clean              remove models/
#   make help               list the analyses

ANALYSES := $(shell python3 ../tools/build/tee-build.py --list .)

.PHONY: all clean help $(ANALYSES)

all: $(ANALYSES)

$(ANALYSES):
	@python3 ../tools/build/tee-build.py . $@ $(if $(filter command line,$(origin SPEC)),--spec $(SPEC))

clean:
	rm -rf models

help:
	@echo "analyses: $(ANALYSES)"
	@echo "  make A          build A.toml into its output directory (default models/A)"
	@echo "  make A SPEC=DIR the same on a spec checkout"
	@echo "  make clean      remove models/"
