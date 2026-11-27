#!/bin/sh
# Installs nightly Rust and bpf-linker into .tools/, so building the eBPF
# program leaves the rest of the machine alone. The Makefile picks them up.
set -eu

cd "$(dirname "$0")/.."
tools=$PWD/.tools
linker=v0.13.0

mkdir -p "$tools/bin"
export RUSTUP_HOME="$tools/rustup" CARGO_HOME="$tools/cargo"

if [ ! -x "$CARGO_HOME/bin/rustup" ]; then
	curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o "$tools/rustup-init.sh"
	sh "$tools/rustup-init.sh" -y -q --no-modify-path --profile minimal \
		--default-toolchain nightly -c rust-src,clippy,rustfmt
fi

if [ ! -x "$tools/bin/bpf-linker" ]; then
	curl -sSfL "https://github.com/aya-rs/bpf-linker/releases/download/$linker/bpf-linker-x86_64-unknown-linux-musl.tar.zst" |
		tar --zstd -x -C "$tools/bin"
fi

"$CARGO_HOME/bin/rustc" --version
"$tools/bin/bpf-linker" --version
