TEST_DIR := $(shell pwd)/tests

all:	perm

perm:
	$(info set permission)
	@sudo chmod +x ./3rd_party/Darwin64/maude.darwin64 ./3rd_party/Linux64/maude.linux64
	@sudo chmod +x ./scripts/run-exp ./scripts/gen-report ./scripts/gen-table ./scripts/run
	@sudo chmod +x ./docker/run.sh ./docker/build.sh ./docker/copy.sh ./docker/cross.sh
	@sudo chmod +x ./tests/exec

test:
	$(info start smoke test ...)
	@exec $(TEST_DIR)/exec