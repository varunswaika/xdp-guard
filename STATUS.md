# Status

**27 November 2026.** Working. The program loads and behaves as tested, in a VM on the GitHub runner's kernel.

- Host tests pass: token bucket, frame parser, prefix parsing.
- The VM job (virtme-ng) loads the program and the netfilter module as root:
  - the 5 kernel tests pass (`BPF_PROG_TEST_RUN`);
  - end to end over a veth pair, traffic passes, a blocked source is dropped, and of 100 pings at a 10/s limit, 85 were limited (about 15 got through);
  - the module drops all 3 pings from a blocked source.
- Lint (fmt, clippy, ShellCheck) is clean.

Not measured: drop rate in packets per second.

Next:

1. Measure drop rate against iptables raw and conntrack with xdp-trafficgen, and publish one figure.
2. Then mark it complete.
