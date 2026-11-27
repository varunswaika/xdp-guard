# Status

**27 November 2026.** Working on the host side, unproven in the kernel.

- Host tests pass: token bucket, frame parser, prefix parsing.
- The eBPF program and the netfilter module build. Neither has been loaded.
- Kernel tests, a veth end-to-end script and a VM CI job are written but have not run.

Next:

1. Run the VM job and fix what the verifier or the tests find.
2. Measure drop rate against plain iptables on a veth pair.
