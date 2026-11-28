# How it works and how it is tested

Each frame is checked before the kernel builds an skb for it. The program finds the source address (IPv4 or IPv6, behind up to two VLAN tags), drops it if it falls in a blocked prefix, then charges it to a token bucket for that source. Buckets live in an LRU hash, so a flood of spoofed sources pushes out old entries instead of filling the map. ARP and anything the program cannot read pass untouched and are counted.

The maps are pinned under `/sys/fs/bpf/xdp-guard`, so the CLI can change the rules and read the counters while the filter runs.

`nf/` holds a small netfilter module in C that does the block list part at `PRE_ROUTING`, for comparison. It runs later than XDP and pays for an skb per packet, but it needs no driver support.

## The netfilter module

```sh
make -C nf
sudo insmod nf/xdp_guard_nf.ko blocked=192.0.2.1,198.51.100.7
cat /proc/net/xdp_guard_nf
```

## What is tested where

Loading an eBPF program needs root, which the machine this was written on does not give. So the tests are split by what they need. The root tests run in CI inside a virtme-ng VM on the GitHub runner's kernel.

| What | Where | Run so far |
| --- | --- | --- |
| Token bucket: bursts, refill rate, a sustained flood, clock going backwards, overflow at huge rates | `xdp-guard-common`, host (`make check`) | Yes, passing |
| Frame parser: IPv4, IPv6, VLAN and QinQ, bad versions and header lengths, a frame cut at every length | `xdp-guard-common`, host | Yes, passing |
| Prefix parsing, block list files, IPv4-mapped keys | `xdp-guard`, host | Yes, passing |
| fmt, clippy with `-D warnings`, ShellCheck | host (`make lint`) | Yes, clean |
| eBPF program builds; the object has no unresolved calls | host, nightly and `bpf-linker` | Yes, and loaded in the VM job |
| Netfilter module builds with `W=1` and passes `checkpatch.pl` | host, Linux 7.3.6 headers | Yes, and loaded in the VM job |
| The verifier accepts the program; frames run through it with `BPF_PROG_TEST_RUN` give the right verdicts and counters (5 tests) | `xdp-guard/tests/kernel.rs`, root only (`make kernel-test`) | Yes, 5 of 5 pass in the VM job |
| The CLI attaches to a veth, blocks and limits real pings, and detaches cleanly | `tests/vm/e2e.sh`, root | Yes, in the VM job. Of 100 pings at a 10/s limit, 85 were limited, so about 15 got through |
| The module loads and drops a blocked source | `tests/vm/nf.sh`, root | Yes, in the VM job: 3 of 3 pings from a blocked source dropped |
| All of the above in CI | `.github/workflows/ci.yml`, and `vm.yml` boots the runner's kernel with virtme-ng | Yes, both green |

Not measured yet: drop rate in packets per second, against iptables. A veth pair can only give a ratio, not figures comparable with the XDP paper's 24 Mpps on one core.

## Layout

- `xdp-guard-common/`: the parser and token bucket, shared by the program and the CLI, `no_std`.
- `xdp-guard-ebpf/`: the XDP program and its maps.
- `xdp-guard/`: the CLI. Its `build.rs` builds the eBPF program and embeds it.
- `nf/`: the netfilter module.
- `tests/vm/`: scripts the VM job runs as root.
