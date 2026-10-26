//! Compile the LSM programs in `bpf/` with clang. The object carries CO-RE
//! relocations, which Aya resolves against the running kernel's BTF at load
//! time, so one build works across kernel versions.

use std::{env, path::PathBuf, process::Command};

use anyhow::{Context as _, Result, bail};

fn main() -> Result<()> {
    let clang = env::var("CLANG").unwrap_or_else(|_| "clang".into());
    let out = PathBuf::from(env::var("OUT_DIR")?).join("explsm");
    let status = Command::new(&clang)
        .args(["-target", "bpf", "-O2", "-g", "-Wall", "-Werror"])
        .args(["-c", "bpf/explsm.bpf.c", "-o"])
        .arg(&out)
        .status()
        .with_context(|| format!("failed to run {clang}"))?;
    if !status.success() {
        bail!("{clang} failed to compile bpf/explsm.bpf.c");
    }
    println!("cargo:rerun-if-changed=bpf");
    println!("cargo:rerun-if-env-changed=CLANG");
    Ok(())
}
