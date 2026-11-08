# Cloud run report

An unattended run on branch `release-hardening` (2026-11-08/09). What was
done, what CI says, what was skipped and why, and what is still open.

## 1. CI

Done:

- `tests/run-all.sh` (in the VM, as root): starts a private system bus with
  `packaging/org.explsm.Daemon1.conf` when none runs, runs each smoke test
  in its own process group with a timeout, prints one table, exits 1 on any
  failure, takes test names (`--list`), `--logs DIR`, `--slow N`.
- `tests/vm-smoke.sh` (host, normal user): builds the release and the
  `test-answer` agent in `target/smoke`, boots `vng` with `bpf` added to
  `lsm=`, shares `target/vm-smoke-logs` writable, runs run-all.sh as root
  and returns its status. `--kernel PATH|vX.Y`, TCG without `/dev/kvm`.
- `.github/workflows/ci.yml`: job `check` (fmt, clippy `-D warnings`, test,
  release build, `--locked`) and job `vm-smoke` on Ubuntu mainline kernels
  6.9, 6.15 and 7.3.3 (KVM through a udev rule, kernels cached, actions
  pinned to SHAs, logs uploaded as artifacts).
- A "Testing" section in the README.

Bugs found by running the smoke tests in a VM:

- **Kernel oops on 6.9.** A denied create in a protected folder crashed the
  kernel (NULL dereference in the `inode_create` program). 6.9's verifier
  takes `dentry->d_inode` of a trusted dentry for non-NULL, drops the NULL
  check as dead code and emits a plain load. Every `d_inode` read now goes
  through `bpf_probe_read_kernel`.
- The sandbox unit test failed on kernels without securityfs or Landlock
  ABI 9.
- The smoke tests gave explsmd 5 s to attach, too little under emulation,
  and refused an agent binary cargo had not relinked as stale.

## 2. §9 Who started the app

## 3. §5 Guarded binaries

## CI status

## Skipped, and why

## Open concerns
