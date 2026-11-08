//! Derive `LAYOUT_VERSION` from the BPF side's shared header and map
//! definitions (`layout.rs`), so a change to them can't ship without a new
//! version, and a comment can't make one.

use std::{env, fs, path::PathBuf};

include!("layout.rs");

fn main() {
    let dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let bpf = dir.join("../explsmd/bpf");
    let header = bpf.join("explsm.h");
    let object = bpf.join("explsm.bpf.c");
    let read = |p: &PathBuf| {
        fs::read_to_string(p).unwrap_or_else(|e| panic!("reading {}: {e}", p.display()))
    };
    let version = layout_version(&read(&header), &read(&object));
    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("layout.rs");
    fs::write(
        &out,
        format!("pub const LAYOUT_VERSION: u32 = {version:#010x};\n"),
    )
    .unwrap();
    println!("cargo:rerun-if-changed={}", header.display());
    println!("cargo:rerun-if-changed={}", object.display());
    println!("cargo:rerun-if-changed=layout.rs");
}
