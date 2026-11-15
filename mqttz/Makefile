# The analyses of MQT-TZ: the tables of mqttz.toml other than [spec] and [ta] (see README.md).
#
#   make model-checking     build models/model-checking (tools/build/tee-build.py): the spec of
#                           mqttz.toml, fetched into ../build/spec/, built and transformed with the
#                           settings of [model-checking], with core/ and the preprocessed TA
#   make                    every analysis
#   make A SPEC=DIR         the analysis A on a spec checkout instead of the revision of mqttz.toml
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
	@echo "  make A          build models/A"
	@echo "  make A SPEC=DIR the same on a spec checkout"
	@echo "  make clean      remove models/"
