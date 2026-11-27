use which::which;

// Cargo cannot see that this crate needs bpf-linker, so rebuild when it changes.
fn main() {
    let linker = which("bpf-linker").expect("bpf-linker is not on PATH");
    println!("cargo:rerun-if-changed={}", linker.display());
}
