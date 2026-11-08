//! The LSM hooks explsm attaches to, with the arguments its programs expect
//! (`LSM_PROG` in `bpf/explsm.bpf.c`), checked against the running kernel's
//! BTF before anything is loaded. The verifier only catches a program that
//! reads past the last argument; one whose hook gained or reordered
//! arguments would read the wrong ones.
//!
//! A hook whose signature changed between supported kernels has a program
//! for each, and the one that matches is loaded: `bpf` gained its `kernel`
//! argument in Linux 6.15. A hook that matches none stops the start.
//!
//! Aya's `Btf` does not expose the types it parses, so the few BTF kinds
//! needed are read here.

use std::{collections::HashMap, fmt};

use anyhow::{Context as _, Result, bail};

pub const KERNEL_BTF: &str = "/sys/kernel/btf/vmlinux";

/// One argument: a pointer to the named type (`struct inode`, `char`,
/// `void`), or an integer of any width (`int`, `bool`, `umode_t`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Arg {
    Ptr(&'static str),
    Scalar,
}

impl fmt::Display for Arg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Arg::Ptr(name) => write!(f, "{name} *"),
            Arg::Scalar => f.write_str("integer"),
        }
    }
}

/// An argument as the kernel's BTF has it.
#[derive(PartialEq, Eq, Debug)]
enum KernelArg {
    Ptr(String),
    Scalar,
}

impl KernelArg {
    fn is(&self, arg: &Arg) -> bool {
        match (self, arg) {
            (KernelArg::Ptr(k), Arg::Ptr(a)) => k == a,
            (KernelArg::Scalar, Arg::Scalar) => true,
            _ => false,
        }
    }
}

impl fmt::Display for KernelArg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KernelArg::Ptr(name) => write!(f, "{name} *"),
            KernelArg::Scalar => f.write_str("integer"),
        }
    }
}

/// A program, the hook it is for, and the hook's arguments as it reads them
/// (without the previous verdict). Programs for the same hook follow each
/// other, in order of preference.
struct Sig {
    prog: &'static str,
    hook: &'static str,
    args: &'static [Arg],
}

/// A program to load and the hook to attach it to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Hook {
    pub prog: &'static str,
    pub hook: &'static str,
}

use Arg::{Ptr, Scalar};

const TASK: Arg = Ptr("struct task_struct");
const INODE: Arg = Ptr("struct inode");
const DENTRY: Arg = Ptr("struct dentry");
const IDMAP: Arg = Ptr("struct mnt_idmap");
const STR: Arg = Ptr("char");

const fn sig(prog: &'static str, hook: &'static str, args: &'static [Arg]) -> Sig {
    Sig { prog, hook, args }
}

/// Programs that give processes their identity. Attached before seeding,
/// so running apps have their identity before anything they do is looked
/// at.
const IDENTITY: &[Sig] = &[
    sig("task_alloc", "task_alloc", &[TASK, Scalar]),
    sig(
        "bprm_committed_creds",
        "bprm_committed_creds",
        &[Ptr("struct linux_binprm")],
    ),
];

/// Programs that check accesses. Attached after seeding.
const ACCESS: &[Sig] = &[
    sig("file_open", "file_open", &[Ptr("struct file")]),
    sig("inode_create", "inode_create", &[INODE, DENTRY, Scalar]),
    sig("inode_mkdir", "inode_mkdir", &[INODE, DENTRY, Scalar]),
    sig(
        "inode_mknod",
        "inode_mknod",
        &[INODE, DENTRY, Scalar, Scalar],
    ),
    sig("inode_symlink", "inode_symlink", &[INODE, DENTRY, STR]),
    sig("inode_link", "inode_link", &[DENTRY, INODE, DENTRY]),
    sig("inode_unlink", "inode_unlink", &[INODE, DENTRY]),
    sig("inode_rmdir", "inode_rmdir", &[INODE, DENTRY]),
    sig(
        "inode_rename",
        "inode_rename",
        &[INODE, DENTRY, INODE, DENTRY],
    ),
    sig(
        "inode_setattr",
        "inode_setattr",
        &[IDMAP, DENTRY, Ptr("struct iattr")],
    ),
    sig(
        "inode_setxattr",
        "inode_setxattr",
        &[IDMAP, DENTRY, STR, Ptr("void"), Scalar, Scalar],
    ),
    sig(
        "inode_removexattr",
        "inode_removexattr",
        &[IDMAP, DENTRY, STR],
    ),
    sig(
        "inode_set_acl",
        "inode_set_acl",
        &[IDMAP, DENTRY, STR, Ptr("struct posix_acl")],
    ),
    sig(
        "inode_remove_acl",
        "inode_remove_acl",
        &[IDMAP, DENTRY, STR],
    ),
    sig(
        "ptrace_access_check",
        "ptrace_access_check",
        &[TASK, Scalar],
    ),
    sig("ptrace_traceme", "ptrace_traceme", &[TASK]),
    sig(
        "task_kill",
        "task_kill",
        &[
            TASK,
            Ptr("struct kernel_siginfo"),
            Scalar,
            Ptr("struct cred"),
        ],
    ),
    sig(
        "task_setrlimit",
        "task_setrlimit",
        &[TASK, Scalar, Ptr("struct rlimit")],
    ),
    sig(
        "mmap_file",
        "mmap_file",
        &[Ptr("struct file"), Scalar, Scalar, Scalar],
    ),
    sig(
        "file_mprotect",
        "file_mprotect",
        &[Ptr("struct vm_area_struct"), Scalar, Scalar],
    ),
    sig("bpf_map", "bpf_map", &[Ptr("struct bpf_map"), Scalar]),
    sig("bpf_prog", "bpf_prog", &[Ptr("struct bpf_prog")]),
    // 6.15 and later, then 6.9 to 6.14.
    sig(
        "bpf",
        "bpf",
        &[Scalar, Ptr("union bpf_attr"), Scalar, Scalar],
    ),
    sig(
        "bpf_noflag",
        "bpf",
        &[Scalar, Ptr("union bpf_attr"), Scalar],
    ),
];

/// The programs that match the running kernel.
pub struct Selected {
    pub identity: Vec<Hook>,
    pub access: Vec<Hook>,
}

impl Selected {
    pub fn all(&self) -> impl Iterator<Item = &Hook> {
        self.identity.iter().chain(&self.access)
    }
}

/// Pick, for each hook, the program whose arguments are the kernel's.
pub fn select(btf: &[u8]) -> Result<Selected> {
    let btf = KernelBtf::parse(btf).context("reading the kernel's BTF")?;
    let mut errors = Vec::new();
    let mut pick = |sigs: &[Sig]| {
        let mut out = Vec::new();
        for (i, s) in sigs.iter().enumerate() {
            if i > 0 && sigs[i - 1].hook == s.hook {
                continue;
            }
            let variants = sigs[i..].iter().take_while(|v| v.hook == s.hook);
            let Some(kernel) = btf.hook_args(s.hook) else {
                errors.push(format!("the kernel has no {} hook", s.hook));
                continue;
            };
            let same = |v: &&Sig| {
                kernel.len() == v.args.len() && kernel.iter().zip(v.args).all(|(k, a)| k.is(a))
            };
            match variants.clone().find(same) {
                Some(v) => out.push(Hook {
                    prog: v.prog,
                    hook: v.hook,
                }),
                None => errors.push(format!(
                    "{}({}), expected {}",
                    s.hook,
                    list(&kernel),
                    variants
                        .map(|v| format!("({})", list(v.args)))
                        .collect::<Vec<_>>()
                        .join(" or ")
                )),
            }
        }
        out
    };
    let selected = Selected {
        identity: pick(IDENTITY),
        access: pick(ACCESS),
    };
    if !errors.is_empty() {
        bail!(
            "this kernel's LSM hooks are not the ones explsm was written for (Linux 6.9 or \
             newer is supported), nothing is loaded:\n    {}",
            errors.join("\n    ")
        );
    }
    Ok(selected)
}

fn list<T: fmt::Display>(args: &[T]) -> String {
    args.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

// BTF kinds (include/uapi/linux/btf.h).
const INT: u32 = 1;
const PTR: u32 = 2;
const ARRAY: u32 = 3;
const STRUCT: u32 = 4;
const UNION: u32 = 5;
const ENUM: u32 = 6;
const FWD: u32 = 7;
const TYPEDEF: u32 = 8;
const VOLATILE: u32 = 9;
const CONST: u32 = 10;
const RESTRICT: u32 = 11;
const FUNC: u32 = 12;
const FUNC_PROTO: u32 = 13;
const VAR: u32 = 14;
const DATASEC: u32 = 15;
const FLOAT: u32 = 16;
const DECL_TAG: u32 = 17;
const TYPE_TAG: u32 = 18;
const ENUM64: u32 = 19;

#[derive(Clone, Copy)]
struct Type {
    name: u32,
    kind: u32,
    kflag: bool,
    vlen: usize,
    /// Size or referenced type.
    ty: u32,
    /// Offset of the data after the common part.
    extra: usize,
}

/// The parts of a BTF blob needed to read hook signatures.
struct KernelBtf<'a> {
    data: &'a [u8],
    strings: &'a [u8],
    /// Index = type id - 1.
    types: Vec<Type>,
    /// `bpf_lsm_<hook>` functions by name.
    hooks: HashMap<&'a str, u32>,
}

fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(data.get(at..at + 4)?.try_into().ok()?))
}

impl<'a> KernelBtf<'a> {
    fn parse(data: &'a [u8]) -> Result<Self> {
        let magic = data.get(..2).map(|m| u16::from_ne_bytes([m[0], m[1]]));
        if magic != Some(0xeb9f) {
            bail!("not BTF of this byte order");
        }
        let field = |i: usize| u32_at(data, 4 + 4 * i).map(|v| v as usize);
        let (Some(hdr_len), Some(type_off), Some(type_len), Some(str_off), Some(str_len)) =
            (field(0), field(1), field(2), field(3), field(4))
        else {
            bail!("short header");
        };
        let types_at = hdr_len + type_off;
        let strings = data
            .get(hdr_len + str_off..hdr_len + str_off + str_len)
            .context("strings out of bounds")?;
        let end = types_at + type_len;
        if end > data.len() {
            bail!("types out of bounds");
        }
        let mut types = Vec::new();
        let mut at = types_at;
        while at < end {
            let (Some(name), Some(info), Some(ty)) =
                (u32_at(data, at), u32_at(data, at + 4), u32_at(data, at + 8))
            else {
                bail!("truncated type");
            };
            let kind = (info >> 24) & 0x1f;
            let vlen = (info & 0xffff) as usize;
            let extra = at + 12;
            let len = match kind {
                INT | VAR | DECL_TAG => 4,
                ARRAY => 12,
                STRUCT | UNION | DATASEC | ENUM64 => 12 * vlen,
                ENUM | FUNC_PROTO => 8 * vlen,
                PTR | FWD | TYPEDEF | VOLATILE | CONST | RESTRICT | FUNC | FLOAT | TYPE_TAG => 0,
                other => bail!("unknown BTF kind {other}"),
            };
            types.push(Type {
                name,
                kind,
                kflag: info >> 31 != 0,
                vlen,
                ty,
                extra,
            });
            at = extra + len;
        }
        let mut btf = Self {
            data,
            strings,
            types,
            hooks: HashMap::new(),
        };
        for (i, t) in btf.types.iter().enumerate() {
            if t.kind == FUNC
                && let Some(hook) = btf.str(t.name).strip_prefix("bpf_lsm_")
            {
                btf.hooks.insert(hook, i as u32 + 1);
            }
        }
        Ok(btf)
    }

    fn str(&self, off: u32) -> &'a str {
        let s = self.strings.get(off as usize..).unwrap_or_default();
        let s = &s[..s.iter().position(|&b| b == 0).unwrap_or(s.len())];
        std::str::from_utf8(s).unwrap_or_default()
    }

    fn get(&self, id: u32) -> Option<Type> {
        self.types.get((id as usize).checked_sub(1)?).copied()
    }

    /// Follow typedefs and qualifiers. `None` is void.
    fn strip(&self, mut id: u32) -> Option<Type> {
        for _ in 0..32 {
            let t = self.get(id)?;
            match t.kind {
                TYPEDEF | VOLATILE | CONST | RESTRICT | TYPE_TAG => id = t.ty,
                _ => return Some(t),
            }
        }
        None
    }

    /// The arguments of `hook`, `None` if the kernel has no such hook.
    fn hook_args(&self, hook: &str) -> Option<Vec<KernelArg>> {
        let func = self.get(*self.hooks.get(hook)?)?;
        let proto = self.get(func.ty).filter(|p| p.kind == FUNC_PROTO)?;
        let mut args = Vec::new();
        for i in 0..proto.vlen {
            let ty = u32_at(self.data, proto.extra + 8 * i + 4)?;
            args.push(self.arg(ty));
        }
        Some(args)
    }

    fn arg(&self, ty: u32) -> KernelArg {
        let Some(t) = self.strip(ty) else {
            return KernelArg::Ptr("?".into());
        };
        match t.kind {
            INT | ENUM | ENUM64 => KernelArg::Scalar,
            PTR => KernelArg::Ptr(match self.strip(t.ty) {
                None => "void".into(),
                Some(p) => match p.kind {
                    STRUCT => format!("struct {}", self.str(p.name)),
                    UNION => format!("union {}", self.str(p.name)),
                    FWD if p.kflag => format!("union {}", self.str(p.name)),
                    FWD => format!("struct {}", self.str(p.name)),
                    _ => self.str(p.name).into(),
                },
            }),
            _ => KernelArg::Ptr("?".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn running_kernel_matches() {
        let Ok(data) = std::fs::read(KERNEL_BTF) else {
            eprintln!("no {KERNEL_BTF}; skipped");
            return;
        };
        let selected = select(&data).unwrap();
        assert_eq!(selected.identity.len(), IDENTITY.len());
        assert_eq!(selected.access.len(), ACCESS.len() - 1);
        assert!(selected.access.iter().any(|h| h.hook == "bpf"));
    }

    #[test]
    fn not_btf() {
        assert!(select(b"not btf at all").is_err());
    }
}
