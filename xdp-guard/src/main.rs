use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context as _, Result};
use aya::programs::XdpMode;
use clap::{Parser, Subcommand, ValueEnum};
use xdp_guard::{Cidr, Guard, cidr, guard};
use xdp_guard_common::{Limit, PIN_DIR};

/// A per-source rate limiter and block list in XDP.
///
/// `attach` pins the program and its maps under /sys/fs/bpf/xdp-guard; the
/// other commands work on the running filter from there.
#[derive(Parser)]
#[command(version)]
struct Cli {
    /// Where the link and maps are pinned
    #[arg(long, default_value = PIN_DIR, global = true)]
    pin_dir: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Load the filter and attach it to an interface
    Attach {
        interface: String,
        #[arg(long, value_enum, default_value_t = Mode::Auto)]
        mode: Mode,
    },
    /// Detach the filter and remove its pinned maps
    Detach,
    /// Drop all traffic from these addresses or prefixes
    Block {
        prefixes: Vec<Cidr>,
        /// Read more prefixes from a file, one per line
        #[arg(short, long)]
        file: Option<PathBuf>,
    },
    /// Take prefixes off the block list
    Unblock {
        #[arg(required = true)]
        prefixes: Vec<Cidr>,
    },
    /// Print the block list
    Blocks,
    /// Limit each source to RATE packets a second, or `off`
    Limit {
        rate: Rate,
        /// Packets a quiet source may send at once [default: RATE]
        burst: Option<u64>,
    },
    /// Print the limit and the counters
    Stats,
    /// Print the sources the limit drops most
    Top {
        #[arg(short, default_value_t = 10)]
        n: usize,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Mode {
    /// Driver mode if the driver supports it, else generic
    Auto,
    /// Generic mode, in the kernel's network stack
    Skb,
    /// Native mode, in the driver
    Driver,
}

#[derive(Clone, Copy)]
enum Rate {
    Off,
    PerSecond(u64),
}

impl FromStr for Rate {
    type Err = String;

    fn from_str(s: &str) -> Result<Rate, String> {
        match s {
            "off" => Ok(Rate::Off),
            _ => s
                .parse()
                .map(Rate::PerSecond)
                .map_err(|_| format!("`{s}` is not a rate or `off`")),
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let dir = cli.pin_dir.as_path();
    match cli.command {
        Command::Attach { interface, mode } => {
            let mode = match mode {
                Mode::Auto => XdpMode::Default,
                Mode::Skb => XdpMode::Skb,
                Mode::Driver => XdpMode::Driver,
            };
            guard::attach(dir, &interface, mode)?;
            println!("attached to {interface}");
        }
        Command::Detach => {
            guard::detach(dir)?;
            println!("detached");
        }
        Command::Block { mut prefixes, file } => {
            if let Some(file) = file {
                let text = fs::read_to_string(&file)
                    .with_context(|| format!("reading {}", file.display()))?;
                prefixes.extend(cidr::parse_list(&text).map_err(anyhow::Error::msg)?);
            }
            let mut guard = Guard::open(dir)?;
            for prefix in &prefixes {
                guard.block(*prefix)?;
            }
            println!("blocked {} prefixes", prefixes.len());
        }
        Command::Unblock { prefixes } => {
            let mut guard = Guard::open(dir)?;
            for prefix in prefixes {
                guard.unblock(prefix)?;
            }
        }
        Command::Blocks => {
            for prefix in Guard::open(dir)?.blocks()? {
                println!("{prefix}");
            }
        }
        Command::Limit { rate, burst } => {
            let limit = match rate {
                Rate::Off => Limit::OFF,
                Rate::PerSecond(rate) => {
                    Limit::new(rate, burst.unwrap_or(rate)).map_err(anyhow::Error::msg)?
                }
            };
            Guard::open(dir)?.set_limit(limit)?;
        }
        Command::Stats => stats(dir)?,
        Command::Top { n } => {
            println!("{:<40} {:>12} {:>12}", "source", "dropped", "passed");
            for (addr, bucket) in Guard::open(dir)?.top(n)? {
                println!("{addr:<40} {:>12} {:>12}", bucket.dropped, bucket.passed);
            }
        }
    }
    Ok(())
}

fn stats(dir: &Path) -> Result<()> {
    let guard = Guard::open(dir)?;
    let limit = guard.limit()?;
    if limit.is_on() {
        println!("{:<10} {}/s, burst {}", "limit", limit.rate, limit.burst);
    } else {
        println!("{:<10} off", "limit");
    }
    for (counter, value) in guard.counters()? {
        println!("{:<10} {value}", counter.name());
    }
    Ok(())
}
