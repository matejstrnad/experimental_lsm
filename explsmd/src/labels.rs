//! What the daemon puts on disk and finds there at startup.
//!
//! - The label: `security.bpf.explsm` on every root, an inspectable marker of
//!   the owner. The BPF side does not read it (no kfuncs from Aya yet), but
//!   only the daemon may change it.
//! - Hard links: a file inside a tree with more than one link can also be
//!   reached through a path outside the tree, where the `d_parent` walk
//!   would not find the root. Such files are added to `ROOTS` themselves.

use std::{
    ffi::CString,
    fs, io,
    os::{
        fd::{AsRawFd as _, OwnedFd},
        unix::{ffi::OsStrExt as _, fs::MetadataExt as _},
    },
    path::{Path, PathBuf},
};

use explsm_common::{FileKey, LABEL_XATTR};
use explsm_policy::resolve::key_of;

/// A path that reaches exactly the inode of `fd`, wherever it was moved.
pub fn fd_path(fd: &OwnedFd) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()))
}

fn c_path(path: &Path) -> io::Result<CString> {
    Ok(CString::new(path.as_os_str().as_bytes())?)
}

fn label_name() -> CString {
    CString::new(LABEL_XATTR).expect("no NUL in the label name")
}

/// Set the label on `path`, following symlinks like the resolution of roots
/// to inodes.
pub fn write_label(path: &Path, value: &str) -> io::Result<()> {
    let path = c_path(path)?;
    let ret = unsafe {
        libc::setxattr(
            path.as_ptr(),
            label_name().as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Remove the label from `path`. A label that is not there is not an error.
pub fn remove_label(path: &Path) -> io::Result<()> {
    let path = c_path(path)?;
    let ret = unsafe { libc::removexattr(path.as_ptr(), label_name().as_ptr()) };
    if ret == 0 {
        return Ok(());
    }
    let e = io::Error::last_os_error();
    if e.raw_os_error() == Some(libc::ENODATA) {
        Ok(())
    } else {
        Err(e)
    }
}

#[derive(Default)]
pub struct Scan {
    /// Files with more than one hard link.
    pub linked: Vec<FileKey>,
    /// Entries that could not be read, with the reason.
    pub errors: Vec<(String, io::Error)>,
}

/// Find the multiply linked files below `root`. Symlinks are not followed
/// and other filesystems mounted inside the tree are skipped (mounts inside
/// a tree are not covered by the walk either).
pub fn scan_links(root: &Path) -> Scan {
    let mut scan = Scan::default();
    match fs::symlink_metadata(root) {
        Ok(md) if md.is_dir() => walk(root, md.dev(), &mut scan),
        Ok(_) => {}
        Err(e) => scan.errors.push((root.display().to_string(), e)),
    }
    scan
}

fn walk(dir: &Path, dev: u64, scan: &mut Scan) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => return scan.errors.push((dir.display().to_string(), e)),
    };
    for entry in entries {
        let path = match entry {
            Ok(e) => e.path(),
            Err(e) => {
                scan.errors.push((dir.display().to_string(), e));
                continue;
            }
        };
        let md = match fs::symlink_metadata(&path) {
            Ok(md) => md,
            Err(e) => {
                scan.errors.push((path.display().to_string(), e));
                continue;
            }
        };
        if md.dev() != dev {
            continue;
        }
        if md.is_dir() {
            walk(&path, dev, scan);
        } else if md.nlink() > 1 && !md.file_type().is_symlink() {
            scan.linked.push(key_of(&md));
        }
    }
}
