# Simple Makefile for Zig project
# Usage examples:
#   make build                     # compile
#   make test                      # run all tests
#   make run ARGS="--help"         # run the binary with args
#   make test-file FILE=src/main.zig              # run tests in a single file
#   make test-file FILE=src/root.zig FILTER="basic add functionality"
#   make fmt / make fmt-check      # format code / check formatting
#   make clean                     # remove build artifacts

ZIG ?= zig
OPT ?= Debug
ARGS ?=

.PHONY: all build run test test-file fmt fmt-check clean

all: build

build:
	$(ZIG) build -Doptimize=$(OPT)

run:
	$(ZIG) build -Doptimize=$(OPT) run -- $(ARGS)

# Run the entire test suite via `zig build test` as recommended.
test:
	$(ZIG) build test -Doptimize=$(OPT)

# Run tests in a single file; optionally filter by name/pattern with FILTER="..."
# Example: make test-file FILE=src/main.zig FILTER="simple test"
test-file:
	@if [ -z "$(FILE)" ]; then \
	  echo "Usage: make test-file FILE=src/<file>.zig [FILTER=pattern]"; \
	  exit 2; \
	fi; \
	EXTRA=""; \
	if [ -n "$(FILTER)" ]; then EXTRA="--test-filter $(FILTER)"; fi; \
	$(ZIG) test $(FILE) $$EXTRA

fmt:
	$(ZIG) fmt .

fmt-check:
	$(ZIG) fmt --check .

clean:
	rm -rf zig-out .zig-cache
