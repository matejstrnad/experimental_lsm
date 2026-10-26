//! Pinning: the maps and links live in bpffs, so explsm keeps enforcing
//! after explsmd exits, and the next explsmd takes over where it stopped.
//!
//! Maps are pinned by name (`pinning` in their BTF definitions) and reused by
//! the next load; `CONFIG[CFG_LAYOUT]` tells whether they are of the same
//! layout. Each program's link is pinned as `link-<prog>`. A new link
//! replaces the old one by a rename, so the old program stays attached until
//! the new one is. Removing the pins detaches everything.
//!
//! Only the daemon may change the pin directory (`OWNER_PINS`) or get file
//! descriptors for explsm's objects (`OWN_IDS`), root included.

use std::{
    fs, io,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result};
use aya::{maps::MapData, programs::links::FdLink};

pub const PIN_DIR: &str = "/sys/fs/bpf/explsm";

/// Name of the pin of a program's link.
fn link_name(prog: &str) -> String {
    format!("link-{prog}")
}

pub struct Pins {
    pub dir: PathBuf,
    /// Pin the links. Without, they are held by the daemon and end with it,
    /// and the directory is removed on exit (`--no-pin`).
    pub keep: bool,
    /// Links that are not pinned.
    held: Vec<FdLink>,
}

impl Pins {
    pub fn new(dir: PathBuf, keep: bool) -> Result<Self> {
        fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        Ok(Self {
            dir,
            keep,
            held: Vec::new(),
        })
    }

    /// Whether an earlier run left its maps here.
    pub fn reused(&self) -> bool {
        self.dir.join("CONFIG").exists()
    }

    /// Keep the link of `prog` attached; returns its id.
    pub fn link(&mut self, prog: &str, link: FdLink) -> Result<u32> {
        let id = link.info().with_context(|| format!("link of {prog}"))?.id();
        if !self.keep {
            self.held.push(link);
            return Ok(id);
        }
        let path = self.dir.join(link_name(prog));
        // bpffs refuses names with a dot.
        let tmp = self.dir.join(format!("{}-new", link_name(prog)));
        let _ = fs::remove_file(&tmp);
        // Dropping the PinnedLink closes our fd; the pin keeps the link.
        link.pin(&tmp)
            .with_context(|| format!("pinning the link of {prog}"))?;
        fs::rename(&tmp, &path).with_context(|| format!("replacing {}", path.display()))?;
        Ok(id)
    }

    /// Ids of the pinned maps.
    pub fn map_ids(&self) -> Result<Vec<u32>> {
        let mut ids = Vec::new();
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let name = entry.file_name();
            if name.to_string_lossy().starts_with("link-") {
                continue;
            }
            let map = MapData::from_pin(entry.path())
                .with_context(|| format!("opening the pinned map {}", entry.path().display()))?;
            ids.push(map.info()?.id());
        }
        Ok(ids)
    }
}

/// Remove the pins in `dir` and `dir` itself: links first, which detaches the
/// programs, then the maps. Returns whether there was anything.
pub fn unload(dir: &Path) -> io::Result<bool> {
    let entries: Vec<PathBuf> = match fs::read_dir(dir) {
        Ok(e) => e.flatten().map(|e| e.path()).collect(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    let is_link = |p: &PathBuf| {
        p.file_name()
            .is_some_and(|n| n.to_string_lossy().starts_with("link-"))
    };
    for path in entries.iter().filter(|p| is_link(p)) {
        fs::remove_file(path)?;
    }
    for path in entries.iter().filter(|p| !is_link(p)) {
        fs::remove_file(path)?;
    }
    fs::remove_dir(dir)?;
    Ok(true)
}
