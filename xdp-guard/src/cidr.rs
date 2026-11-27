//! Address prefixes for the block lists.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// An address and prefix length, with the host bits cleared.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Cidr {
    addr: IpAddr,
    len: u8,
}

impl Cidr {
    pub fn new(addr: IpAddr, len: u8) -> Result<Cidr, String> {
        let addr = match addr {
            IpAddr::V4(a) if len <= 32 => {
                let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
                IpAddr::V4(Ipv4Addr::from(u32::from(a) & mask))
            }
            IpAddr::V6(a) if len <= 128 => {
                let mask = u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0);
                IpAddr::V6(Ipv6Addr::from(u128::from(a) & mask))
            }
            _ => return Err(format!("prefix length {len} is too long for {addr}")),
        };
        Ok(Cidr { addr, len })
    }

    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    pub fn prefix_len(&self) -> u32 {
        u32::from(self.len)
    }
}

impl FromStr for Cidr {
    type Err = String;

    fn from_str(s: &str) -> Result<Cidr, String> {
        let (addr, len) = match s.split_once('/') {
            Some((addr, len)) => (addr, Some(len)),
            None => (s, None),
        };
        let addr: IpAddr = addr
            .parse()
            .map_err(|_| format!("`{addr}` is not an IP address"))?;
        let len = match len {
            Some(len) => len
                .parse()
                .map_err(|_| format!("`{len}` is not a prefix length"))?,
            None if addr.is_ipv4() => 32,
            None => 128,
        };
        Cidr::new(addr, len)
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}

/// Reads a block list file: one prefix per line, `#` starts a comment.
pub fn parse_list(text: &str) -> Result<Vec<Cidr>, String> {
    let mut prefixes = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if !line.is_empty() {
            prefixes.push(line.parse().map_err(|e| format!("line {}: {e}", i + 1))?);
        }
    }
    Ok(prefixes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cidr(s: &str) -> Cidr {
        s.parse().unwrap()
    }

    #[test]
    fn bare_addresses_are_hosts() {
        assert_eq!(cidr("192.0.2.1").to_string(), "192.0.2.1/32");
        assert_eq!(cidr("2001:db8::1").to_string(), "2001:db8::1/128");
    }

    #[test]
    fn host_bits_are_cleared() {
        assert_eq!(cidr("192.0.2.77/24").to_string(), "192.0.2.0/24");
        assert_eq!(cidr("10.1.2.3/9").to_string(), "10.0.0.0/9");
        assert_eq!(
            cidr("2001:db8:aaaa::1/36").to_string(),
            "2001:db8:a000::/36"
        );
    }

    #[test]
    fn zero_length_matches_everything() {
        assert_eq!(cidr("203.0.113.9/0").to_string(), "0.0.0.0/0");
        assert_eq!(cidr("2001:db8::1/0").to_string(), "::/0");
    }

    #[test]
    fn rejects_nonsense() {
        assert!("192.0.2.1/33".parse::<Cidr>().is_err());
        assert!("2001:db8::/129".parse::<Cidr>().is_err());
        assert!("192.0.2/24".parse::<Cidr>().is_err());
        assert!("192.0.2.1/x".parse::<Cidr>().is_err());
        assert!("".parse::<Cidr>().is_err());
    }

    #[test]
    fn list_files_allow_comments_and_blanks() {
        let text = "# bad actors\n192.0.2.0/24\n\n2001:db8::/32  # docs range\n";
        let list = parse_list(text).unwrap();
        assert_eq!(list, vec![cidr("192.0.2.0/24"), cidr("2001:db8::/32")]);
    }

    #[test]
    fn list_errors_name_the_line() {
        let err = parse_list("192.0.2.0/24\nnope\n").unwrap_err();
        assert!(err.starts_with("line 2:"), "{err}");
    }
}
