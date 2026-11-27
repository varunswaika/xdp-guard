# Uses the toolchain in .tools/ when scripts/tools.sh has installed one.
ifneq ($(wildcard .tools/cargo/bin/cargo),)
export RUSTUP_HOME := $(CURDIR)/.tools/rustup
export PATH := $(CURDIR)/.tools/cargo/bin:$(CURDIR)/.tools/bin:$(PATH)
endif

CARGO_FLAGS ?= -j2

build:
	cargo build $(CARGO_FLAGS) --release

check:
	cargo test $(CARGO_FLAGS)

lint:
	cargo fmt --all --check
	cargo clippy $(CARGO_FLAGS) --all-targets -- -D warnings
	shellcheck scripts/*.sh tests/vm/*.sh

# Needs root: loads the program and runs frames through it.
kernel-test:
	cargo test $(CARGO_FLAGS) --test kernel -- --ignored --test-threads=1

module:
	$(MAKE) -C nf

.PHONY: build check lint kernel-test module
