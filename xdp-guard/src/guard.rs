//! The running filter, reached through its pinned link and maps.

use std::ffi::CString;
use std::fs;
use std::net::{IpAddr, Ipv6Addr};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use aya::maps::lpm_trie::Key;
use aya::maps::{Array, HashMap, LpmTrie, Map, MapData, PerCpuArray};
use aya::programs::links::{FdLink, PinnedLink};
use aya::programs::{Xdp, XdpMode};
use aya::{Ebpf, EbpfLoader};
use xdp_guard_common::{Bucket, Counter, Limit, maps};

use crate::cidr::Cidr;

/// The compiled XDP program, built by build.rs.
pub static PROGRAM: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/xdp-guard"));

const LINK: &str = "link";

/// Loads the program with its maps pinned in `dir`. Maps already pinned
/// there are reused, so a reload keeps the block lists.
pub fn load(dir: &Path) -> Result<Ebpf> {
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let mut ebpf = EbpfLoader::new()
        .default_map_pin_directory(dir)
        .load(PROGRAM)
        .context("loading the program's maps")?;
    program(&mut ebpf)?
        .load()
        .context("loading the program into the kernel")?;
    Ok(ebpf)
}

pub fn program(ebpf: &mut Ebpf) -> Result<&mut Xdp> {
    let program = ebpf
        .program_mut("xdp_guard")
        .context("the object has no xdp_guard program")?;
    Ok(program.try_into()?)
}

/// Loads the program, attaches it to `interface` and pins the link, so the
/// filter stays up after this process exits.
pub fn attach(dir: &Path, interface: &str, mode: XdpMode) -> Result<()> {
    if dir.join(LINK).exists() {
        bail!("already attached; run `xdp-guard detach` first");
    }
    let mut ebpf = load(dir)?;
    let program = program(&mut ebpf)?;
    let name = CString::new(interface).context("bad interface name")?;
    let id = program
        .attach(name.as_c_str(), mode)
        .with_context(|| format!("attaching to {interface}"))?;
    let link = FdLink::try_from(program.take_link(id)?)
        .context("this kernel cannot pin XDP links (needs Linux 5.9 or later)")?;
    link.pin(dir.join(LINK)).context("pinning the link")?;
    Ok(())
}

/// Detaches the filter and removes everything pinned in `dir`.
pub fn detach(dir: &Path) -> Result<()> {
    let link = dir.join(LINK);
    if link.exists() {
        // Dropping the last reference to the link detaches the program.
        drop(PinnedLink::from_pin(&link)?.unpin()?);
    }
    for name in maps::ALL {
        let path = dir.join(name);
        if path.exists() {
            fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
        }
    }
    if dir.exists() {
        fs::remove_dir(dir).with_context(|| format!("removing {}", dir.display()))?;
    }
    Ok(())
}

pub struct Guard {
    block_v4: LpmTrie<MapData, [u8; 4], u8>,
    block_v6: LpmTrie<MapData, [u8; 16], u8>,
    buckets: HashMap<MapData, [u8; 16], Bucket>,
    limit: Array<MapData, Limit>,
    counters: PerCpuArray<MapData, u64>,
}

fn open(dir: &Path, name: &str) -> Result<Map> {
    let path: PathBuf = dir.join(name);
    let data = MapData::from_pin(&path)
        .with_context(|| format!("opening {}; is the filter attached?", path.display()))?;
    Ok(Map::from_map_data(data)?)
}

impl Guard {
    pub fn open(dir: &Path) -> Result<Guard> {
        Ok(Guard {
            block_v4: open(dir, maps::BLOCK_V4)?.try_into()?,
            block_v6: open(dir, maps::BLOCK_V6)?.try_into()?,
            buckets: open(dir, maps::BUCKETS)?.try_into()?,
            limit: open(dir, maps::LIMIT)?.try_into()?,
            counters: open(dir, maps::COUNTERS)?.try_into()?,
        })
    }

    pub fn block(&mut self, prefix: Cidr) -> Result<()> {
        match prefix.addr() {
            IpAddr::V4(a) => {
                self.block_v4
                    .insert(&Key::new(prefix.prefix_len(), a.octets()), &1, 0)?
            }
            IpAddr::V6(a) => {
                self.block_v6
                    .insert(&Key::new(prefix.prefix_len(), a.octets()), &1, 0)?
            }
        }
        Ok(())
    }

    pub fn unblock(&mut self, prefix: Cidr) -> Result<()> {
        let removed = match prefix.addr() {
            IpAddr::V4(a) => self
                .block_v4
                .remove(&Key::new(prefix.prefix_len(), a.octets())),
            IpAddr::V6(a) => self
                .block_v6
                .remove(&Key::new(prefix.prefix_len(), a.octets())),
        };
        removed.with_context(|| format!("{prefix} is not in the block list"))
    }

    pub fn blocks(&self) -> Result<Vec<Cidr>> {
        let v4 = self
            .block_v4
            .keys()
            .map(|k| k.map(|k| (IpAddr::from(k.data()), k.prefix_len())));
        let v6 = self
            .block_v6
            .keys()
            .map(|k| k.map(|k| (IpAddr::from(k.data()), k.prefix_len())));
        let mut list = Vec::new();
        for entry in v4.chain(v6) {
            let (addr, len) = entry?;
            list.push(Cidr::new(addr, len as u8).map_err(anyhow::Error::msg)?);
        }
        list.sort();
        Ok(list)
    }

    pub fn limit(&self) -> Result<Limit> {
        Ok(self.limit.get(&0, 0)?)
    }

    /// Sets the limit and forgets every bucket, so the new limit starts
    /// from full buckets rather than from credit earned under the old one.
    pub fn set_limit(&mut self, limit: Limit) -> Result<()> {
        self.limit.set(0, &limit, 0)?;
        let keys: Vec<[u8; 16]> = self.buckets.keys().collect::<Result<_, _>>()?;
        for key in keys {
            // A source can age out of the LRU between listing and removal.
            let _ = self.buckets.remove(&key);
        }
        Ok(())
    }

    /// Each counter summed over all CPUs.
    pub fn counters(&self) -> Result<Vec<(Counter, u64)>> {
        Counter::ALL
            .iter()
            .map(|&c| Ok((c, self.counters.get(&(c as u32), 0)?.iter().sum())))
            .collect()
    }

    /// Sources the rate limit has dropped, most dropped first.
    pub fn top(&self, n: usize) -> Result<Vec<(IpAddr, Bucket)>> {
        let mut sources: Vec<(IpAddr, Bucket)> = self
            .buckets
            .iter()
            .map(|entry| entry.map(|(key, bucket)| (source_addr(key), bucket)))
            .collect::<Result<_, _>>()?;
        sources.retain(|(_, b)| b.dropped > 0);
        sources.sort_by(|a, b| b.1.dropped.cmp(&a.1.dropped).then(a.0.cmp(&b.0)));
        sources.truncate(n);
        Ok(sources)
    }
}

/// Undoes the IPv4 mapping the XDP program uses for bucket keys.
fn source_addr(key: [u8; 16]) -> IpAddr {
    let addr = Ipv6Addr::from(key);
    match addr.to_ipv4_mapped() {
        Some(v4) => IpAddr::V4(v4),
        None => IpAddr::V6(addr),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xdp_guard_common::Source;

    #[test]
    fn bucket_keys_map_back_to_addresses() {
        let v4 = Source::V4([192, 0, 2, 9]).key();
        assert_eq!(source_addr(v4), "192.0.2.9".parse::<IpAddr>().unwrap());
        let v6: Ipv6Addr = "2001:db8::7".parse().unwrap();
        assert_eq!(source_addr(Source::V6(v6.octets()).key()), IpAddr::V6(v6));
    }
}
