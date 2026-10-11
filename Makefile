SLANGC ?= slangc

.PHONY: test bench
test:
	SLANGC="$(SLANGC)" sh ./tests/run.sh

bench:
	SLANGC="$(SLANGC)" sh ./bench/run.sh
