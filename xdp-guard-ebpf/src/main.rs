//! The XDP program. Per packet: find the source address, drop it if a block
//! list covers it, drop it if its token bucket is empty, count the outcome.
//! The parsing and bucket arithmetic live in `xdp-guard-common`.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action::{XDP_DROP, XDP_PASS},
    helpers::bpf_ktime_get_ns,
    macros::{map, xdp},
    maps::{Array, LpmTrie, LruHashMap, PerCpuArray, lpm_trie::Key},
    programs::XdpContext,
};
use xdp_guard_common::{
    Bucket, Bytes, COUNTER_SLOTS, Counter, Limit, MAX_BLOCKS, MAX_SOURCES, Parsed, Source, packet,
};

#[map]
static BLOCK_V4: LpmTrie<[u8; 4], u8> = LpmTrie::pinned(MAX_BLOCKS, 0);

#[map]
static BLOCK_V6: LpmTrie<[u8; 16], u8> = LpmTrie::pinned(MAX_BLOCKS, 0);

#[map]
static BUCKETS: LruHashMap<[u8; 16], Bucket> = LruHashMap::pinned(MAX_SOURCES, 0);

#[map]
static LIMIT: Array<Limit> = Array::pinned(1, 0);

#[map]
static COUNTERS: PerCpuArray<u64> = PerCpuArray::pinned(COUNTER_SLOTS, 0);

#[xdp]
pub fn xdp_guard(ctx: XdpContext) -> u32 {
    let (action, counter) = match packet::source(&Frame(&ctx)) {
        Parsed::Ip(source) if blocked(source) => (XDP_DROP, Counter::Blocked),
        Parsed::Ip(source) if !admit(source) => (XDP_DROP, Counter::Limited),
        Parsed::Ip(_) => (XDP_PASS, Counter::Passed),
        Parsed::NotIp => (XDP_PASS, Counter::NotIp),
        // Not ours to judge: the stack drops what it cannot parse.
        Parsed::Malformed => (XDP_PASS, Counter::Malformed),
    };
    if let Some(n) = COUNTERS.get_ptr_mut(counter as u32) {
        unsafe { *n += 1 };
    }
    action
}

/// The packet as the verifier wants it read: each load checked against
/// `data_end` before it happens.
struct Frame<'a>(&'a XdpContext);

impl Bytes for Frame<'_> {
    #[inline(always)]
    fn load<const N: usize>(&self, offset: usize) -> Option<[u8; N]> {
        let start = self.0.data() + offset;
        if start + N > self.0.data_end() {
            return None;
        }
        Some(unsafe { core::ptr::read_unaligned(start as *const [u8; N]) })
    }
}

#[inline(always)]
fn blocked(source: Source) -> bool {
    match source {
        Source::V4(addr) => BLOCK_V4.get(&Key::new(32, addr)).is_some(),
        Source::V6(addr) => BLOCK_V6.get(&Key::new(128, addr)).is_some(),
    }
}

#[inline(always)]
fn admit(source: Source) -> bool {
    let limit = match LIMIT.get(0) {
        Some(limit) if limit.is_on() => *limit,
        _ => return true,
    };
    let now = unsafe { bpf_ktime_get_ns() };
    let key = source.key();
    // Two CPUs can race on one bucket; the worst case is a packet or two
    // over the limit, which is cheaper than a lock on every packet.
    match BUCKETS.get_ptr_mut(&key) {
        Some(bucket) => unsafe { (*bucket).admit(&limit, now) },
        None => {
            let mut bucket = Bucket::full(&limit, now);
            let pass = bucket.admit(&limit, now);
            let _ = BUCKETS.insert(&key, &bucket, 0);
            pass
        }
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
