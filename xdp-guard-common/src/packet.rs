//! Finds a frame's source address.
//!
//! The parser reads through [`Bytes`], never a slice, because the verifier
//! only accepts packet reads that are checked against the end of the packet
//! one by one. The XDP program implements `Bytes` with those checks; tests
//! use the slice implementation.

const ETH_HLEN: usize = 14;
const VLAN_HLEN: usize = 4;
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;
const ETH_P_8021Q: u16 = 0x8100;
const ETH_P_8021AD: u16 = 0x88a8;

/// Bounds-checked reads of packet bytes.
pub trait Bytes {
    /// The `N` bytes at `offset`, or `None` if the packet is too short.
    fn load<const N: usize>(&self, offset: usize) -> Option<[u8; N]>;
}

impl Bytes for [u8] {
    fn load<const N: usize>(&self, offset: usize) -> Option<[u8; N]> {
        let end = offset.checked_add(N)?;
        self.get(offset..end)?.try_into().ok()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    V4([u8; 4]),
    V6([u8; 16]),
}

impl Source {
    /// The address as an IPv6 key, with IPv4 mapped into `::ffff:0:0/96`,
    /// so one bucket map serves both families.
    pub fn key(self) -> [u8; 16] {
        match self {
            Source::V6(a) => a,
            Source::V4(a) => (0xffff << 32 | u128::from(u32::from_be_bytes(a))).to_be_bytes(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Parsed {
    Ip(Source),
    NotIp,
    Malformed,
}

/// Reads an Ethernet frame, with up to two VLAN tags, down to the IP source.
#[inline(always)]
pub fn source<P: Bytes + ?Sized>(frame: &P) -> Parsed {
    parse(frame).unwrap_or(Parsed::Malformed)
}

#[inline(always)]
fn parse<P: Bytes + ?Sized>(frame: &P) -> Option<Parsed> {
    let mut offset = ETH_HLEN;
    let mut ethertype = u16::from_be_bytes(frame.load(offset - 2)?);
    for _ in 0..2 {
        if ethertype != ETH_P_8021Q && ethertype != ETH_P_8021AD {
            break;
        }
        ethertype = u16::from_be_bytes(frame.load(offset + 2)?);
        offset += VLAN_HLEN;
    }

    match ethertype {
        ETH_P_IP => {
            let [version_ihl] = frame.load(offset)?;
            if version_ihl >> 4 != 4 || version_ihl & 0x0f < 5 {
                return Some(Parsed::Malformed);
            }
            Some(Parsed::Ip(Source::V4(frame.load(offset + 12)?)))
        }
        ETH_P_IPV6 => {
            let [version] = frame.load(offset)?;
            if version >> 4 != 6 {
                return Some(Parsed::Malformed);
            }
            Some(Parsed::Ip(Source::V6(frame.load(offset + 8)?)))
        }
        _ => Some(Parsed::NotIp),
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;
    use std::vec::Vec;

    fn ethernet(tags: &[u16], ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&[0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2]);
        for tpid in tags {
            f.extend_from_slice(&tpid.to_be_bytes());
            f.extend_from_slice(&[0x00, 0x2a]);
        }
        f.extend_from_slice(&ethertype.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    fn ipv4(src: [u8; 4]) -> Vec<u8> {
        let mut h = vec![0x45, 0, 0, 20, 0, 0, 0x40, 0, 64, 17, 0, 0];
        h.extend_from_slice(&src);
        h.extend_from_slice(&[10, 0, 0, 1]);
        h
    }

    fn ipv6(src: [u8; 16]) -> Vec<u8> {
        let mut h = vec![0x60, 0, 0, 0, 0, 0, 17, 64];
        h.extend_from_slice(&src);
        h.extend_from_slice(&[0; 16]);
        h
    }

    const V6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7];

    #[test]
    fn ipv4_source() {
        let f = ethernet(&[], ETH_P_IP, &ipv4([192, 0, 2, 9]));
        assert_eq!(source(&f[..]), Parsed::Ip(Source::V4([192, 0, 2, 9])));
    }

    #[test]
    fn ipv6_source() {
        let f = ethernet(&[], ETH_P_IPV6, &ipv6(V6));
        assert_eq!(source(&f[..]), Parsed::Ip(Source::V6(V6)));
    }

    #[test]
    fn vlan_and_qinq() {
        let one = ethernet(&[ETH_P_8021Q], ETH_P_IP, &ipv4([198, 51, 100, 1]));
        assert_eq!(source(&one[..]), Parsed::Ip(Source::V4([198, 51, 100, 1])));
        let two = ethernet(&[ETH_P_8021AD, ETH_P_8021Q], ETH_P_IPV6, &ipv6(V6));
        assert_eq!(source(&two[..]), Parsed::Ip(Source::V6(V6)));
    }

    #[test]
    fn three_tags_is_not_ip() {
        let f = ethernet(
            &[ETH_P_8021AD, ETH_P_8021Q, ETH_P_8021Q],
            ETH_P_IP,
            &ipv4([1, 2, 3, 4]),
        );
        assert_eq!(source(&f[..]), Parsed::NotIp);
    }

    #[test]
    fn arp_is_not_ip() {
        let f = ethernet(&[], 0x0806, &[0; 28]);
        assert_eq!(source(&f[..]), Parsed::NotIp);
    }

    #[test]
    fn wrong_version_is_malformed() {
        let mut p = ipv4([1, 2, 3, 4]);
        p[0] = 0x65;
        assert_eq!(source(&ethernet(&[], ETH_P_IP, &p)[..]), Parsed::Malformed);
        let mut p = ipv4([1, 2, 3, 4]);
        p[0] = 0x44;
        assert_eq!(source(&ethernet(&[], ETH_P_IP, &p)[..]), Parsed::Malformed);
        let mut p = ipv6(V6);
        p[0] = 0x40;
        assert_eq!(
            source(&ethernet(&[], ETH_P_IPV6, &p)[..]),
            Parsed::Malformed
        );
    }

    #[test]
    fn every_truncation_is_handled() {
        let frames = [
            ethernet(&[ETH_P_8021Q], ETH_P_IP, &ipv4([192, 0, 2, 9])),
            ethernet(&[ETH_P_8021AD, ETH_P_8021Q], ETH_P_IPV6, &ipv6(V6)),
        ];
        for f in &frames {
            let full = source(&f[..]);
            for len in 0..f.len() {
                let cut = source(&f[..len]);
                assert!(
                    cut == Parsed::Malformed || cut == full,
                    "len {len}: {cut:?}"
                );
            }
        }
    }

    #[test]
    fn ipv4_keys_are_mapped() {
        assert_eq!(
            Source::V4([192, 0, 2, 9]).key(),
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 9]
        );
        assert_eq!(Source::V6(V6).key(), V6);
    }
}
