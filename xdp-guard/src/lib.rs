//! Userspace side of xdp-guard: loading and attaching the XDP program, and
//! reading and writing its maps. The binary in main.rs is a thin CLI over
//! this, and the kernel tests in `tests/` drive the same code.

pub mod cidr;
pub mod guard;

pub use cidr::Cidr;
pub use guard::Guard;
