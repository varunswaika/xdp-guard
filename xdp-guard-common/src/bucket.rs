//! A token bucket per source address.
//!
//! Credit is kept in nanopackets: a packet costs one second's worth
//! (`NS_PER_SEC`), and every nanosecond adds `rate`. That keeps the refill
//! exact in integer arithmetic, with no division on the packet path except
//! one to find how long the bucket takes to fill.

const NS_PER_SEC: u64 = 1_000_000_000;

/// The rate limit, as the CLI writes it into the `LIMIT` map.
/// A rate of zero turns limiting off.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Limit {
    /// Packets per second, sustained.
    pub rate: u64,
    /// Packets a quiet source may send at once.
    pub burst: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LimitError {
    ZeroRate,
    ZeroBurst,
    BurstTooLarge,
}

impl core::fmt::Display for LimitError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            LimitError::ZeroRate => "rate must be at least 1 packet per second",
            LimitError::ZeroBurst => "burst must be at least 1 packet",
            LimitError::BurstTooLarge => "burst is too large",
        })
    }
}

impl Limit {
    pub const OFF: Limit = Limit { rate: 0, burst: 0 };

    pub fn new(rate: u64, burst: u64) -> Result<Limit, LimitError> {
        if rate == 0 {
            return Err(LimitError::ZeroRate);
        }
        if burst == 0 {
            return Err(LimitError::ZeroBurst);
        }
        if burst.checked_mul(NS_PER_SEC).is_none() {
            return Err(LimitError::BurstTooLarge);
        }
        Ok(Limit { rate, burst })
    }

    pub fn is_on(&self) -> bool {
        self.rate != 0
    }

    fn capacity(&self) -> u64 {
        self.burst.saturating_mul(NS_PER_SEC)
    }
}

/// One source's bucket, as stored in the `BUCKETS` map.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Bucket {
    pub credit: u64,
    pub stamp_ns: u64,
    pub passed: u64,
    pub dropped: u64,
}

impl Bucket {
    /// A bucket for a source seen for the first time: full.
    pub fn full(limit: &Limit, now_ns: u64) -> Bucket {
        Bucket {
            credit: limit.capacity(),
            stamp_ns: now_ns,
            passed: 0,
            dropped: 0,
        }
    }

    /// Refills for the time since the last packet, then takes one packet's
    /// credit if there is enough. Returns whether the packet may pass.
    pub fn admit(&mut self, limit: &Limit, now_ns: u64) -> bool {
        let capacity = limit.capacity();
        let gap = now_ns.saturating_sub(self.stamp_ns);
        // Past this gap the bucket is full whatever the rate, and below it
        // `gap * rate` stays under `capacity`, so it cannot overflow.
        let refill = match capacity.checked_div(limit.rate) {
            Some(fill_ns) if gap < fill_ns => gap * limit.rate,
            _ => capacity,
        };
        let room = capacity.saturating_sub(self.credit);
        self.credit = (self.credit + refill.min(room)).min(capacity);
        self.stamp_ns = self.stamp_ns.max(now_ns);

        if self.credit >= NS_PER_SEC {
            self.credit -= NS_PER_SEC;
            self.passed = self.passed.wrapping_add(1);
            true
        } else {
            self.dropped = self.dropped.wrapping_add(1);
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: u64 = 1_000_000;

    fn send(bucket: &mut Bucket, limit: &Limit, now: u64, count: u32) -> u32 {
        (0..count).filter(|_| bucket.admit(limit, now)).count() as u32
    }

    #[test]
    fn rejects_bad_limits() {
        assert_eq!(Limit::new(0, 5), Err(LimitError::ZeroRate));
        assert_eq!(Limit::new(5, 0), Err(LimitError::ZeroBurst));
        assert_eq!(Limit::new(5, u64::MAX), Err(LimitError::BurstTooLarge));
        assert!(Limit::new(u64::MAX, u64::MAX / NS_PER_SEC).is_ok());
    }

    #[test]
    fn a_new_source_gets_its_burst_then_stops() {
        let limit = Limit::new(10, 5).unwrap();
        let mut b = Bucket::full(&limit, 0);
        assert_eq!(send(&mut b, &limit, 0, 8), 5);
        assert_eq!((b.passed, b.dropped), (5, 3));
    }

    #[test]
    fn refills_at_the_rate() {
        let limit = Limit::new(10, 5).unwrap();
        let mut b = Bucket::full(&limit, 0);
        send(&mut b, &limit, 0, 5);
        // 10 per second is one every 100 ms.
        assert!(!b.admit(&limit, 99 * MS));
        assert!(b.admit(&limit, 100 * MS));
        assert!(!b.admit(&limit, 150 * MS));
        assert_eq!(send(&mut b, &limit, 400 * MS, 10), 3);
    }

    #[test]
    fn sustained_flood_passes_at_the_rate() {
        let limit = Limit::new(1000, 50).unwrap();
        let mut b = Bucket::full(&limit, 0);
        // 10,000 packets a second for 10 seconds, one every 100 us.
        let passed = (0..100_000u64)
            .filter(|i| b.admit(&limit, i * 100_000))
            .count();
        // The burst plus 1000 a second, give or take a packet.
        assert!((10_049..=10_051).contains(&passed), "passed {passed}");
    }

    #[test]
    fn never_holds_more_than_the_burst() {
        let limit = Limit::new(10, 5).unwrap();
        let mut b = Bucket::full(&limit, 0);
        assert_eq!(send(&mut b, &limit, 3_600 * 1_000 * MS, 20), 5);
    }

    #[test]
    fn long_gaps_at_huge_rates_do_not_overflow() {
        let limit = Limit::new(u64::MAX, u64::MAX / NS_PER_SEC).unwrap();
        let mut b = Bucket::full(&limit, 0);
        b.credit = 0;
        assert!(b.admit(&limit, u64::MAX));
        assert_eq!(b.credit, limit.capacity() - NS_PER_SEC);
    }

    #[test]
    fn a_clock_step_backwards_adds_nothing() {
        let limit = Limit::new(10, 1).unwrap();
        let mut b = Bucket::full(&limit, 5_000 * MS);
        assert!(b.admit(&limit, 5_000 * MS));
        assert!(!b.admit(&limit, 1_000 * MS));
        assert_eq!(b.stamp_ns, 5_000 * MS);
        assert!(b.admit(&limit, 5_100 * MS));
    }

    #[test]
    fn a_lower_burst_takes_effect_at_once() {
        let wide = Limit::new(10, 100).unwrap();
        let narrow = Limit::new(10, 2).unwrap();
        let mut b = Bucket::full(&wide, 0);
        assert_eq!(send(&mut b, &narrow, 0, 10), 2);
    }
}
