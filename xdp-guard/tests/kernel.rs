//! Loads the real program into the kernel and runs frames through it with
//! BPF_PROG_TEST_RUN. Needs root, so these are ignored by default; run them
//! with `sudo -E cargo test -- --ignored`, or let the VM job in CI do it.

use std::net::IpAddr;
use std::path::PathBuf;

use aya::Ebpf;
use aya::programs::{TestRun, TestRunOptions};
use xdp_guard::{Cidr, Guard, guard};
use xdp_guard_common::{Counter, Limit};

const XDP_DROP: u32 = 1;
const XDP_PASS: u32 = 2;

struct Filter {
    dir: PathBuf,
    ebpf: Ebpf,
    guard: Guard,
}

impl Filter {
    fn load(test: &str) -> Filter {
        let dir = PathBuf::from(format!("/sys/fs/bpf/xdp-guard-test-{test}"));
        guard::detach(&dir).unwrap();
        let ebpf = guard::load(&dir).expect("loading the program (run as root)");
        let guard = Guard::open(&dir).unwrap();
        Filter { dir, ebpf, guard }
    }

    fn run(&mut self, frame: &[u8]) -> u32 {
        let options = TestRunOptions {
            data_in: Some(frame),
            ..Default::default()
        };
        let program = guard::program(&mut self.ebpf).unwrap();
        program.test_run(options).unwrap().return_value
    }

    fn count(&self, counter: Counter) -> u64 {
        let counters = self.guard.counters().unwrap();
        counters.into_iter().find(|(c, _)| *c == counter).unwrap().1
    }
}

impl Drop for Filter {
    fn drop(&mut self) {
        let _ = guard::detach(&self.dir);
    }
}

fn cidr(s: &str) -> Cidr {
    s.parse().unwrap()
}

fn frame(ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = vec![0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2];
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// An IPv4 UDP datagram with an empty payload. Checksums are left at zero:
/// XDP sees the frame before anything checks them.
fn udp(src: &str) -> Vec<u8> {
    match src.parse::<IpAddr>().unwrap() {
        IpAddr::V4(a) => {
            let mut p = vec![0x45, 0, 0, 28, 0, 0, 0x40, 0, 64, 17, 0, 0];
            p.extend_from_slice(&a.octets());
            p.extend_from_slice(&[10, 0, 0, 1]);
            p.extend_from_slice(&[0x30, 0x39, 0x00, 0x35, 0, 8, 0, 0]);
            frame(0x0800, &p)
        }
        IpAddr::V6(a) => {
            let mut p = vec![0x60, 0, 0, 0, 0, 8, 17, 64];
            p.extend_from_slice(&a.octets());
            p.extend_from_slice(
                &"2001:db8::1"
                    .parse::<std::net::Ipv6Addr>()
                    .unwrap()
                    .octets(),
            );
            p.extend_from_slice(&[0x30, 0x39, 0x00, 0x35, 0, 8, 0, 0]);
            frame(0x86dd, &p)
        }
    }
}

#[test]
#[ignore = "needs root"]
fn passes_traffic_by_default() {
    let mut f = Filter::load("default");
    assert_eq!(f.run(&udp("192.0.2.1")), XDP_PASS);
    assert_eq!(f.run(&udp("2001:db8::2")), XDP_PASS);
    assert_eq!(f.count(Counter::Passed), 2);
}

#[test]
#[ignore = "needs root"]
fn drops_blocked_prefixes() {
    let mut f = Filter::load("block");
    f.guard.block(cidr("192.0.2.0/24")).unwrap();
    f.guard.block(cidr("2001:db8:bad::/48")).unwrap();

    assert_eq!(f.run(&udp("192.0.2.200")), XDP_DROP);
    assert_eq!(f.run(&udp("192.0.3.1")), XDP_PASS);
    assert_eq!(f.run(&udp("2001:db8:bad::9")), XDP_DROP);
    assert_eq!(f.run(&udp("2001:db8:600d::9")), XDP_PASS);
    assert_eq!(f.count(Counter::Blocked), 2);
    assert_eq!(f.count(Counter::Passed), 2);

    f.guard.unblock(cidr("192.0.2.0/24")).unwrap();
    assert_eq!(f.run(&udp("192.0.2.200")), XDP_PASS);
    assert_eq!(f.guard.blocks().unwrap(), vec![cidr("2001:db8:bad::/48")]);
}

#[test]
#[ignore = "needs root"]
fn limits_each_source_to_its_burst() {
    let mut f = Filter::load("limit");
    // One packet a second: the test runs well inside a second, so after the
    // burst of three nothing refills.
    f.guard.set_limit(Limit::new(1, 3).unwrap()).unwrap();

    let verdicts: Vec<u32> = (0..5).map(|_| f.run(&udp("198.51.100.7"))).collect();
    assert_eq!(verdicts, [XDP_PASS, XDP_PASS, XDP_PASS, XDP_DROP, XDP_DROP]);
    // Another source has its own bucket.
    assert_eq!(f.run(&udp("198.51.100.8")), XDP_PASS);
    assert_eq!(f.count(Counter::Limited), 2);

    let top = f.guard.top(10).unwrap();
    assert_eq!(top.len(), 1);
    assert_eq!(top[0].0, "198.51.100.7".parse::<IpAddr>().unwrap());
    assert_eq!((top[0].1.passed, top[0].1.dropped), (3, 2));

    f.guard.set_limit(Limit::OFF).unwrap();
    assert_eq!(f.run(&udp("198.51.100.7")), XDP_PASS);
}

#[test]
#[ignore = "needs root"]
fn blocked_sources_do_not_use_up_a_bucket() {
    let mut f = Filter::load("order");
    f.guard.set_limit(Limit::new(1, 1).unwrap()).unwrap();
    f.guard.block(cidr("203.0.113.5")).unwrap();
    for _ in 0..3 {
        assert_eq!(f.run(&udp("203.0.113.5")), XDP_DROP);
    }
    assert_eq!(f.count(Counter::Blocked), 3);
    assert_eq!(f.count(Counter::Limited), 0);
}

#[test]
#[ignore = "needs root"]
fn lets_through_what_it_cannot_judge() {
    let mut f = Filter::load("other");
    let arp = frame(0x0806, &[0; 28]);
    assert_eq!(f.run(&arp), XDP_PASS);
    let cut = &udp("192.0.2.1")[..20];
    assert_eq!(f.run(cut), XDP_PASS);
    assert_eq!(f.count(Counter::NotIp), 1);
    assert_eq!(f.count(Counter::Malformed), 1);
}
