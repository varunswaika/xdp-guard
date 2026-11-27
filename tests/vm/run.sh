#!/bin/sh
# Runs as root inside the test VM: the kernel tests first, then the CLI
# against real traffic over a veth pair.
#   tests/vm/run.sh <xdp-guard binary> <kernel test binary>
set -eu

cli=$1
kernel_tests=$2

mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf

echo "== kernel tests"
"$kernel_tests" --ignored --test-threads=1

echo "== end to end"
"$(dirname "$0")/e2e.sh" "$cli"
