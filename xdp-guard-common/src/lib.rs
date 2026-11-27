//! What the XDP program and the CLI agree on: map names, value layouts, the
//! packet parser and the token bucket. Both sides compile this crate, so the
//! host tests below exercise the same code the kernel runs.

#![no_std]

pub mod bucket;
pub mod packet;

pub use bucket::{Bucket, Limit, LimitError};
pub use packet::{Bytes, Parsed, Source};

/// Where the CLI pins the program's link and maps.
pub const PIN_DIR: &str = "/sys/fs/bpf/xdp-guard";

pub mod maps {
    pub const BLOCK_V4: &str = "BLOCK_V4";
    pub const BLOCK_V6: &str = "BLOCK_V6";
    pub const BUCKETS: &str = "BUCKETS";
    pub const LIMIT: &str = "LIMIT";
    pub const COUNTERS: &str = "COUNTERS";

    pub const ALL: [&str; 5] = [BLOCK_V4, BLOCK_V6, BUCKETS, LIMIT, COUNTERS];
}

/// Sources tracked at once. The bucket map is an LRU, so the quietest
/// sources are forgotten first.
pub const MAX_SOURCES: u32 = 65_536;
/// Prefixes per block list.
pub const MAX_BLOCKS: u32 = 16_384;

/// Slots in the per-CPU counter array.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Counter {
    Passed = 0,
    Blocked = 1,
    Limited = 2,
    NotIp = 3,
    Malformed = 4,
}

impl Counter {
    pub const ALL: [Counter; 5] = [
        Counter::Passed,
        Counter::Blocked,
        Counter::Limited,
        Counter::NotIp,
        Counter::Malformed,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Counter::Passed => "passed",
            Counter::Blocked => "blocked",
            Counter::Limited => "limited",
            Counter::NotIp => "not_ip",
            Counter::Malformed => "malformed",
        }
    }
}

pub const COUNTERS: u32 = Counter::ALL.len() as u32;

#[cfg(feature = "user")]
mod pod {
    // SAFETY: both are repr(C), made only of u64 fields, with no padding.
    unsafe impl aya::Pod for crate::Bucket {}
    unsafe impl aya::Pod for crate::Limit {}
}
