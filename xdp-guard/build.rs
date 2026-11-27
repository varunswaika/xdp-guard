use anyhow::{Context as _, anyhow};
// Declared so cargo rebuilds when the program's sources change.
use xdp_guard_ebpf as _;

// Builds the XDP program with the nightly toolchain and bpf-linker, so that
// `include_bytes_aligned!` in main.rs finds it in OUT_DIR.
fn main() -> anyhow::Result<()> {
    let metadata = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("cargo metadata")?;
    let ebpf = metadata
        .packages
        .iter()
        .find(|p| p.name.as_str() == "xdp-guard-ebpf")
        .ok_or_else(|| anyhow!("xdp-guard-ebpf is not in the workspace"))?;
    let root = ebpf
        .manifest_path
        .parent()
        .ok_or_else(|| anyhow!("no parent for {}", ebpf.manifest_path))?;
    let package = aya_build::Package {
        name: ebpf.name.as_str(),
        root_dir: root.as_str(),
        ..Default::default()
    };
    aya_build::build_ebpf([package], aya_build::Toolchain::default())
}
