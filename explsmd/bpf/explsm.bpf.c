// SPDX-License-Identifier: MIT OR GPL-2.0
/* explsm LSM programs: the enforcement engine.
 *
 * - bprm_committed_creds: exe inode -> app id in task storage. An exec of an
 *   unknown exe drops any inherited identity, unless the task's app has
 *   AF_INHERIT (APP_FLAGS): then it keeps it. A terminal entry exe
 *   (TERMINALS) sets TF_TERMINAL, an app exe clears it.
 * - task_alloc: a child inherits its parent's identity and flags on
 *   fork/clone.
 * - file_open and the inode_* hooks: find the owner of the object (inode
 *   storage cache, then a bounded d_parent walk to a root in ROOTS) and check
 *   the subject against it.
 *
 * Decision: the owner may do anything; otherwise, with @root bypass on, a
 * task with fsuid 0 may too; otherwise the perms must be in
 * GRANTS[(subject, owner)] | GRANTS[(subject, *)], plus the @terminal grants
 * for an unconfined task with TF_TERMINAL and a controlling tty, plus what the
 * user allowed through a prompt (TEMP_GRANTS). A missing perm is reported, and
 * denied with EACCES if the owner is in enforce mode. The daemon may list
 * everything, to find hard links in the trees.
 *
 * An app creating a folder right in one of CLAIM_PARENTS (~, ~/.config, …) is
 * reported, so the user can be asked whether the app should own it.
 *
 * Renames and links never move data between owners in place: a rename or
 * link whose source and destination have different owners gets EXDEV
 * (enforce) so mv falls back to copy + unlink, which are checked one by one.
 * That keeps every cached owner valid. Protected roots are exempt: their
 * identity is their inode, so their data keeps its owner wherever they go.
 * A rename that replaces a root (an atomic save of an owned file) makes what
 * replaced it the root, in ROOTS right away.
 *
 * The label xattr may only be set or removed by the daemon, in every mode and
 * with no root bypass.
 *
 * Hardening (Phase 5):
 * - An app exec'd with LD_PRELOAD, LD_LIBRARY_PATH or LD_AUDIT runs
 *   unconfined: the loader would run foreign code with its identity, unless
 *   the policy allows that exact string for the app (ALLOWED_ENV). So does
 *   one exec'd in a user namespace other than the initial one, where its user
 *   may have mounted its own libraries or /etc/ld.so.preload over the real
 *   ones. An exec by a task of an AF_INHERIT app that keeps its identity is
 *   not checked: the app itself chose the environment and the namespace.
 * - ptrace and everything that goes through ptrace_may_access (/proc/<pid>/
 *   mem, environ, fd/, process_vm_*, pidfd_getfd) on an app's task is only
 *   for the same app, the daemon, and root with the bypass on. So are the
 *   signals that dump core and changes to its resource limits (which can
 *   make it dump core): the dump would hold its memory.
 * - Nothing but the app may add entries to the directory of a user-writable
 *   app exe (EXE_DIRS), or rename or remove that directory and the ones
 *   above it that a user could (EXE_PATHS); the exe itself is in ROOTS like
 *   owned data.
 * - explsm's own files are owned by APP_DAEMON (readable by all, changed by
 *   the daemon, or root with the bypass) and the pin directory by OWNER_PINS
 *   (changed by the daemon only). Only the daemon may get a file descriptor
 *   for explsm's maps, programs and links (OWN_IDS).
 *
 * Kernel struct accesses are CO-RE relocated (see vmlinux.h), so the object
 * runs on any kernel with BTF and the same hook signatures. Programs read
 * their arguments as ctx[n]; the last one is the previous LSM's verdict.
 */

#include "bpf.h"
#include "explsm.h"

#define EPERM 1
#define EACCES 13
#define EXDEV 18

#define S_IFMT 0170000
#define S_IFDIR 0040000

#define O_ACCMODE 3
#define O_WRONLY 1
#define O_RDWR 2

/* ia_valid bits from include/linux/fs.h. */
#define ATTR_MODE (1 << 0)
#define ATTR_UID (1 << 1)
#define ATTR_GID (1 << 2)
#define ATTR_SIZE (1 << 3)
#define ATTR_ATIME (1 << 4)
#define ATTR_MTIME (1 << 5)
#define ATTR_CTIME (1 << 6)
#define ATTR_ATIME_SET (1 << 7)
#define ATTR_MTIME_SET (1 << 8)
#define ATTR_FORCE (1 << 9)
#define ATTR_TIMES_SET (1 << 16)
#define ATTR_META                                                              \
	(ATTR_MODE | ATTR_UID | ATTR_GID | ATTR_ATIME | ATTR_MTIME |           \
	 ATTR_CTIME | ATTR_ATIME_SET | ATTR_MTIME_SET | ATTR_TIMES_SET)

/* A PATH_CHAIN component is read into one half of the path buffer, so
 * offsets stay provably in bounds. */
#define CHAIN_HALF (PATH_LEN / 2)

/* Subject identity per task. Userspace seeds already-running tasks through
 * pidfds. */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_info);
} TASKS SEC(".maps");

/* Cached owner per inode, valid for one policy generation. */
struct {
	__uint(type, BPF_MAP_TYPE_INODE_STORAGE);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct inode_cache);
} INODES SEC(".maps");

/* Executable (dev, ino) -> app id. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 1024);
	__type(key, struct file_key);
	__type(value, app_id);
} EXES SEC(".maps");

/* Protected root (dev, ino) -> owner app id. Also holds files inside a tree
 * that have more than one hard link. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 65536);
	__type(key, struct file_key);
	__type(value, app_id);
} ROOTS SEC(".maps");

/* (subject, owner) -> granted perms. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 4096);
	__type(key, struct grant_key);
	__type(value, u32);
} GRANTS SEC(".maps");

/* Terminal entry exes (dev, ino): terminal emulators, sshd, login. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 256);
	__type(key, struct file_key);
	__type(value, u32);
} TERMINALS SEC(".maps");

/* Folders in which a new folder of an app is reported (dev, ino) -> uid. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 4096);
	__type(key, struct file_key);
	__type(value, u32);
} CLAIM_PARENTS SEC(".maps");

/* Grants from prompts, for one process or one session -> perms. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 4096);
	__type(key, struct temp_key);
	__type(value, u32);
} TEMP_GRANTS SEC(".maps");

/* Directory of a user-writable app exe (dev, ino) -> app id. Only the app
 * may add entries to it, so nobody can plant an exe a glob would match. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 1024);
	__type(key, struct file_key);
	__type(value, app_id);
} EXE_DIRS SEC(".maps");

/* Directories on the way to a user-writable app exe that a user could
 * rename or remove (dev, ino) -> app id: the exe's directory and those of its
 * ancestors whose parent a user can write to. Only the app may, so nobody
 * can move them aside and put a new exe in their place. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 4096);
	__type(key, struct file_key);
	__type(value, app_id);
} EXE_PATHS SEC(".maps");

/* explsm's own maps, programs and links by id: only the daemon may get a
 * file descriptor for them. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 256);
	__type(key, struct own_key);
	__type(value, u32);
} OWN_IDS SEC(".maps");

/* Where explsmd is installed. An exec of that path by root gets APP_DAEMON
 * even when the inode is not in EXES yet, so an upgraded daemon can take
 * over (or unload) the pinned state. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct daemon_path);
} DAEMON_PATH SEC(".maps");

/* Owner app id -> MODE_AUDIT / MODE_ENFORCE. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, MAX_APPS);
	__type(key, u32);
	__type(value, u32);
} MODES SEC(".maps");

/* Owner app id -> AF_* bits. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, MAX_APPS);
	__type(key, u32);
	__type(value, u32);
} APP_FLAGS SEC(".maps");

/* Loader variables (app, "NAME=VALUE") that don't drop the app's identity. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 256);
	__type(key, struct env_key);
	__type(value, u32);
} ALLOWED_ENV SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CONFIG_LEN);
	__type(key, u32);
	__type(value, u32);
} CONFIG SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, STATS_LEN);
	__type(key, u32);
	__type(value, u64);
} STATS SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 4 << 20);
} EVENTS SEC(".maps");

static __always_inline void bump(u32 stat)
{
	u64 *p = bpf_map_lookup_elem(&STATS, &stat);
	if (p)
		*p += 1;
}

static __always_inline u32 config(u32 index)
{
	u32 *v = bpf_map_lookup_elem(&CONFIG, &index);
	return v ? *v : 0;
}

static __always_inline int enforcing(app_id owner)
{
	owner &= ~OWNER_EXE;
	if (owner == APP_UNCONFINED)
		return 0;
	u32 *mode = bpf_map_lookup_elem(&MODES, &owner);
	return mode && *mode == MODE_ENFORCE;
}

/* Whether app keeps its identity across execs of exes that are no app. */
static __always_inline int inherits(app_id app)
{
	if (app == APP_UNCONFINED)
		return 0;
	u32 *flags = bpf_map_lookup_elem(&APP_FLAGS, &app);
	return flags && (*flags & AF_INHERIT);
}

static __always_inline struct file_key file_key(struct inode *inode)
{
	return (struct file_key){ .dev = inode->i_sb->s_dev, .ino = inode->i_ino };
}

static __always_inline struct file_key dentry_key(struct dentry *d)
{
	struct inode *ino = d->d_inode;
	/* Not created yet: the device still names the filesystem. */
	if (!ino)
		return (struct file_key){ .dev = d->d_sb->s_dev };
	return file_key(ino);
}

static __always_inline app_id *root_of(struct inode *ino)
{
	struct file_key key = file_key(ino);
	return bpf_map_lookup_elem(&ROOTS, &key);
}

/* Whether d is itself in ROOTS (a root, or a tracked hard link). */
static __always_inline int is_root(struct dentry *d)
{
	struct inode *ino = d->d_inode;
	return ino && root_of(ino);
}

static __always_inline app_id current_app(void)
{
	struct task_info *info =
		bpf_task_storage_get(&TASKS, bpf_get_current_task_btf(), NULL, 0);
	return info ? info->app_id : APP_UNCONFINED;
}

static __always_inline u32 current_flags(void)
{
	struct task_info *info =
		bpf_task_storage_get(&TASKS, bpf_get_current_task_btf(), NULL, 0);
	return info ? info->flags : 0;
}

/* The exe of the current task; zero for kernel threads. */
static __always_inline struct file_key current_exe(void)
{
	struct mm_struct *mm = bpf_get_current_task_btf()->mm;
	if (!mm)
		return (struct file_key){};
	struct file *exe = mm->exe_file;
	if (!exe)
		return (struct file_key){};
	return file_key(exe->f_inode);
}

static __always_inline u32 current_fsuid(void)
{
	return bpf_get_current_task_btf()->cred->fsuid.val;
}

static __always_inline u32 current_tgid(void)
{
	return bpf_get_current_pid_tgid() >> 32;
}

/* Invalidate every cached owner. Not atomic: two racing bumps may both store
 * the same value, which still differs from every cached one. */
static __always_inline void bump_generation(void)
{
	u32 index = CFG_GENERATION;
	u32 *p = bpf_map_lookup_elem(&CONFIG, &index);
	if (p)
		*p += 1;
}

/* Owner of the object at d: walk from d towards the filesystem root and stop
 * at the first root in ROOTS. A negative dentry (an object about to be
 * created) gets its parent's owner. A walk that runs out is treated as
 * unprotected.
 *
 * Uncached: inode storage only takes trusted inode pointers (hook arguments,
 * file->f_inode), not ones reached through d_inode. */
static __always_inline app_id walk_owner(struct dentry *d)
{
	struct dentry *cur = d;
	for (int i = 0; i < MAX_WALK; i++) {
		struct inode *ino = cur->d_inode;
		if (ino) {
			app_id *owner = root_of(ino);
			if (owner)
				return *owner;
		}
		struct dentry *parent = cur->d_parent;
		if (parent == cur)
			return APP_UNCONFINED;
		cur = parent;
	}
	bump(STAT_WALK_EXHAUSTED);
	return APP_UNCONFINED;
}

/* Owner of ino, a trusted inode pointer, whose dentry is d: from the inode
 * cache, else walked and cached. */
static __always_inline app_id owner_cached(struct inode *ino, struct dentry *d)
{
	u32 generation = config(CFG_GENERATION);
	struct inode_cache *slot = bpf_inode_storage_get(
		&INODES, ino, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (slot && slot->generation == generation) {
		bump(STAT_CACHE_HITS);
		return slot->owner;
	}
	bump(STAT_CACHE_MISSES);
	app_id owner = walk_owner(d);
	if (slot) {
		slot->owner = owner;
		slot->generation = generation;
	}
	return owner;
}

/* Owner of the entry d in directory dir (a trusted pointer to the inode of
 * d's parent): the directory's owner, unless d is itself in ROOTS. */
static __always_inline app_id owner_in(struct inode *dir, struct dentry *d)
{
	struct inode *ino = d->d_inode;
	if (ino) {
		app_id *owner = root_of(ino);
		if (owner)
			return *owner;
	}
	return owner_cached(dir, d->d_parent);
}

/* Perms the policy grants subject on data of owner. */
static __always_inline u32 granted(app_id subject, app_id owner)
{
	struct grant_key key = { .subject = subject, .owner = owner };
	u32 *exact = bpf_map_lookup_elem(&GRANTS, &key);
	key.owner = OWNER_ANY;
	u32 *any = bpf_map_lookup_elem(&GRANTS, &key);
	return (exact ? *exact : 0) | (any ? *any : 0);
}

/* Perms the user granted through a prompt: to this process, and to this app
 * (or, unconfined, this exe) for the session. */
static __always_inline u32 temp_granted(app_id subject, app_id owner)
{
	struct temp_key key = {
		.kind = TK_PROC,
		.uid = (u32)bpf_get_current_uid_gid(),
		.owner = owner,
		.a = current_tgid(),
	};
	u32 *proc = bpf_map_lookup_elem(&TEMP_GRANTS, &key);
	if (subject == APP_UNCONFINED) {
		struct file_key exe = current_exe();
		key.kind = TK_EXE;
		key.a = exe.dev;
		key.b = exe.ino;
	} else {
		key.kind = TK_APP;
		key.a = subject;
	}
	u32 *session = bpf_map_lookup_elem(&TEMP_GRANTS, &key);
	return (proc ? *proc : 0) | (session ? *session : 0);
}

/* Perms in perms that subject lacks on data of owner; 0 if allowed. */
static __always_inline u32 missing(app_id subject, app_id owner, u32 perms)
{
	/* An app exe: its contents are no secret. */
	if (owner & OWNER_EXE) {
		owner &= ~OWNER_EXE;
		perms &= ~(PERM_READ | PERM_LIST);
		if (!perms)
			return 0;
	}
	if (owner == APP_UNCONFINED || subject == owner)
		return 0;
	/* The daemon walks every root for hard links, also with the bypass
	 * off; listing is all it needs. */
	if (subject == APP_DAEMON) {
		perms &= ~PERM_LIST;
		if (!perms)
			return 0;
	}
	bump(STAT_FOREIGN);
	/* explsm's own files: anyone may read them, only the daemon may change
	 * them; root too while bypass is on, except for the pins. No grants. */
	if (owner == APP_DAEMON || owner == OWNER_PINS) {
		perms &= ~(PERM_READ | PERM_LIST);
		if (!perms || subject == APP_DAEMON)
			return 0;
		if (owner == APP_DAEMON && config(CFG_ROOT_BYPASS) &&
		    current_fsuid() == 0)
			return 0;
		return perms;
	}
	if (config(CFG_ROOT_BYPASS) && current_fsuid() == 0)
		return 0;
	u32 lacking = perms & ~granted(subject, owner);
	if (!lacking)
		return 0;
	if (subject == APP_UNCONFINED && (current_flags() & TF_TERMINAL) &&
	    bpf_get_current_task_btf()->signal->tty) {
		lacking &= ~granted(SUBJECT_TERMINAL, owner);
		if (!lacking)
			return 0;
	}
	return lacking & ~temp_granted(subject, owner);
}

/* Reserve an event with the fields every event has. Paths are left to the
 * caller. */
static __always_inline struct event *new_event(u32 kind, app_id subject,
					       app_id owner)
{
	struct event *ev = bpf_ringbuf_reserve(&EVENTS, sizeof(*ev), 0);
	if (!ev) {
		bump(STAT_DROPPED);
		return NULL;
	}
	u64 pid_tgid = bpf_get_current_pid_tgid();
	ev->kind = kind;
	ev->pid = pid_tgid >> 32;
	ev->tid = (u32)pid_tgid;
	ev->uid = (u32)bpf_get_current_uid_gid();
	ev->subject = subject;
	ev->owner = owner & ~OWNER_EXE;
	ev->owner2 = APP_UNCONFINED;
	ev->op = 0;
	ev->perms = 0;
	ev->action = ACTION_AUDIT;
	ev->reason = REASON_PERMS;
	ev->flags = 0;
	ev->file = (struct file_key){};
	ev->path.kind = PATH_NONE;
	ev->path.len = 0;
	ev->path2.kind = PATH_NONE;
	ev->path2.len = 0;
	/* Not read in the sleepable exec hook; the exe is ev->file there. */
	ev->exe = kind == EV_EXEC ? (struct file_key){} : current_exe();
	ev->task_flags = current_flags();
	ev->_pad = 0;
	if (bpf_get_current_comm(ev->comm, sizeof(ev->comm)))
		__builtin_memset(ev->comm, 0, sizeof(ev->comm));
	struct task_struct *leader = bpf_get_current_task_btf()->group_leader;
	if (bpf_probe_read_kernel(ev->proc_comm, sizeof(ev->proc_comm), leader->comm))
		__builtin_memset(ev->proc_comm, 0, sizeof(ev->proc_comm));
	ev->start_time = leader->start_boottime;
	return ev;
}

/* Fill out with the names from d up to its filesystem root, leaf first. Inode
 * hooks get no struct path, so bpf_d_path can't be used. */
static __always_inline void name_chain(struct ev_path *out, struct dentry *d)
{
	u32 off = 0;
	u32 kind = PATH_CHAIN;
	for (int i = 0; i < MAX_CHAIN; i++) {
		struct dentry *parent = d->d_parent;
		if (parent == d) {
			kind = PATH_CHAIN_COMPLETE;
			break;
		}
		if (off >= CHAIN_HALF)
			break;
		long n = bpf_probe_read_kernel_str(out->buf + (off & (CHAIN_HALF - 1)),
						   CHAIN_HALF, d->d_name.name);
		if (n <= 0)
			break;
		off += n;
		d = parent;
	}
	out->kind = kind;
	out->len = off;
}

/* Report a perm check that failed and return the hook result. */
static __always_inline int refuse(u32 op, app_id subject, app_id owner,
				  u32 lacking, u32 flags, struct dentry *d,
				  struct dentry *d2)
{
	int deny = enforcing(owner);
	struct event *ev = new_event(EV_ACCESS, subject, owner);
	if (ev) {
		ev->op = op;
		ev->perms = lacking;
		ev->action = deny ? ACTION_DENY : ACTION_AUDIT;
		ev->flags = flags;
		ev->file = dentry_key(d);
		name_chain(&ev->path, d);
		if (d2)
			name_chain(&ev->path2, d2);
		bpf_ringbuf_submit(ev, 0);
	}
	if (deny) {
		bump(STAT_DENIED);
		return -EACCES;
	}
	bump(STAT_AUDITED);
	return 0;
}

/* Check perms on the object at d, whose owner is owner. */
static __always_inline int check(u32 op, app_id owner, u32 perms, u32 flags,
				 struct dentry *d)
{
	app_id subject = current_app();
	u32 lacking = missing(subject, owner, perms);
	if (!lacking)
		return 0;
	return refuse(op, subject, owner, lacking, flags, d, NULL);
}

/* A rename or link from src (owned by from) to dst (in a tree owned by to)
 * would change the owner of data in place. */
static __always_inline int cross(u32 op, app_id from, app_id to,
				 struct dentry *src, struct dentry *dst)
{
	int deny = enforcing(from) || enforcing(to);
	struct event *ev = new_event(EV_ACCESS, current_app(), from);
	if (ev) {
		ev->owner2 = to & ~OWNER_EXE;
		ev->op = op;
		ev->action = deny ? ACTION_DENY : ACTION_AUDIT;
		ev->reason = REASON_CROSS;
		ev->file = dentry_key(src);
		name_chain(&ev->path, src);
		name_chain(&ev->path2, dst);
		bpf_ringbuf_submit(ev, 0);
	}
	if (deny) {
		bump(STAT_DENIED);
		return -EXDEV;
	}
	/* Audit mode lets ownership change under cached entries. */
	bump(STAT_AUDITED);
	bump_generation();
	return 0;
}

/* Report tampering of subject with owner's process or exe and return the
 * hook result: denied if owner is enforced. d may be NULL. Ptrace probes of
 * ps and the like (PTRACE_MODE_NOAUDIT) are not reported. */
static __always_inline int tamper(u32 op, app_id subject, app_id owner,
				  u32 flags, u32 target, struct dentry *d,
				  int report)
{
	int deny = enforcing(owner);
	struct event *ev = report ? new_event(EV_ACCESS, subject, owner) : NULL;
	if (ev) {
		ev->owner2 = target;
		ev->op = op;
		ev->action = deny ? ACTION_DENY : ACTION_AUDIT;
		ev->reason = REASON_TAMPER;
		ev->flags = flags;
		if (d) {
			ev->file = dentry_key(d);
			name_chain(&ev->path, d);
		}
		bpf_ringbuf_submit(ev, 0);
	}
	bump(STAT_TAMPER);
	if (deny)
		return -EPERM;
	return 0;
}

/* A change that app (from EXE_DIRS or EXE_PATHS, may be NULL) guards: only
 * the app itself, the daemon and root with the bypass may make it. */
static __always_inline int exe_guard(app_id *app, struct dentry *d)
{
	if (!app)
		return 0;
	app_id subject = current_app();
	if (subject == *app || subject == APP_DAEMON)
		return 0;
	if (config(CFG_ROOT_BYPASS) && current_fsuid() == 0)
		return 0;
	return tamper(OP_EXE_DIR, subject, *app, 0, 0, d, 1);
}

/* Adding the entry d to dir. If dir holds a user-writable app exe, only
 * that app may: anything else could be picked up as a new version of it. */
static __always_inline int exe_dir(struct inode *dir, struct dentry *d)
{
	struct file_key key = file_key(dir);
	return exe_guard(bpf_map_lookup_elem(&EXE_DIRS, &key), d);
}

/* Renaming, replacing or removing d. If d is a directory on the way to a
 * user-writable app exe, only that app may. */
static __always_inline int exe_path(struct dentry *d)
{
	struct inode *ino = d->d_inode;
	if (!ino)
		return 0;
	struct file_key key = file_key(ino);
	return exe_guard(bpf_map_lookup_elem(&EXE_PATHS, &key), d);
}

/* Most reads for one exec: argv and envp of up to ~512 KiB, or as many
 * strings. More than that is treated as unreadable. */
#define ENV_STEPS 4096

/* Walk over the argv and envp strings of an exec, which sit one after
 * another in the new process's memory from bprm->p to bprm->exec. */
struct env_scan {
	u64 pos;
	u64 end;
	u32 idx;
	u32 argc;
	u32 total;
	/* pos is in the middle of a string longer than a chunk. */
	u32 cont;
	u32 found;
	u32 _pad;
	/* The string read, with the app it is checked for. */
	struct env_key key;
};

/* Whether the string read into buf (n bytes with the NUL) is prefix with a
 * non-empty value. */
static __always_inline int env_is(const char *buf, long n, const char *prefix,
				  int len)
{
	if (n <= len + 1)
		return 0;
	for (int i = 0; i < len; i++)
		if (buf[i] != prefix[i])
			return 0;
	return 1;
}

/* Whether the string read into s->key (n bytes with the NUL, the rest of
 * the chunk zeroed) is one the policy allows for the app. Longer ones than a
 * chunk never are. */
static __always_inline int env_allowed(struct env_scan *s, long n)
{
	if (n >= ENV_CHUNK)
		return 0;
	return !!bpf_map_lookup_elem(&ALLOWED_ENV, &s->key);
}

static long env_step(u64 index, void *data)
{
	struct env_scan *s = data;
	if (s->idx >= s->total || s->pos >= s->end)
		return 1;
	char *buf = s->key.val;
	/* A constant-size clear: zeroing just the tail after the read would
	 * be a loop on n, which the verifier walks for every n. */
	__builtin_memset(buf, 0, ENV_CHUNK);
	long n = bpf_probe_read_user_str(buf, ENV_CHUNK, (void *)s->pos);
	if (n <= 0) {
		s->found |= ENV_UNREADABLE;
		return 1;
	}
	if (!s->cont && s->idx >= s->argc) {
		u32 bit = 0;
		if (env_is(buf, n, "LD_PRELOAD=", 11))
			bit = ENV_LD_PRELOAD;
		else if (env_is(buf, n, "LD_LIBRARY_PATH=", 16))
			bit = ENV_LD_LIBRARY_PATH;
		else if (env_is(buf, n, "LD_AUDIT=", 9))
			bit = ENV_LD_AUDIT;
		if (bit && !env_allowed(s, n))
			s->found |= bit;
	}
	if (n == ENV_CHUNK) {
		/* Truncated (or exactly that long: then the next read is just
		 * the NUL, which ends the string all the same). */
		s->pos += ENV_CHUNK - 1;
		s->cont = 1;
	} else {
		s->pos += n;
		s->idx++;
		s->cont = 0;
	}
	return 0;
}

/* ENV_* bits of the loader variables set in the environment of bprm that
 * the policy does not allow for app. Not inlined, like is_daemon_path: each
 * has a buffer, and in one stack frame they would not fit. */
static __attribute__((noinline)) u32 tainted_env(struct linux_binprm *bprm,
						 app_id app)
{
	struct env_scan s = {
		.pos = bprm->p,
		.end = bprm->exec,
		.argc = bprm->argc,
		.total = bprm->argc + bprm->envc,
		.key.app = app,
	};
	bpf_loop(ENV_STEPS, env_step, &s, 0);
	if (s.idx < s.total)
		s.found |= ENV_UNREADABLE;
	return s.found;
}

/* Whether bprm is root running explsmd from its install path. */
static __attribute__((noinline)) int is_daemon_path(struct linux_binprm *bprm)
{
	if (bpf_get_current_task_btf()->cred->euid.val != 0)
		return 0;
	u32 zero = 0;
	struct daemon_path *want = bpf_map_lookup_elem(&DAEMON_PATH, &zero);
	if (!want || !want->path[0])
		return 0;
	char got[DAEMON_PATH_LEN];
	long n = bpf_probe_read_kernel_str(got, sizeof(got), bprm->filename);
	if (n <= 0)
		return 0;
	for (int i = 0; i < DAEMON_PATH_LEN; i++) {
		if (got[i] != want->path[i])
			return 0;
		if (!got[i])
			return 1;
	}
	return 0;
}

/* Count an exec that left the task with app's identity, and report it if
 * asked to. */
static __always_inline int exec_as(struct linux_binprm *bprm,
				   struct file_key key, app_id app)
{
	bump(STAT_EXECS);
	if (!config(CFG_LOG_EXECS))
		return 0;

	struct event *ev = new_event(EV_EXEC, app, APP_UNCONFINED);
	if (!ev)
		return 0;
	ev->file = key;
	ev->path.kind = PATH_FULL;
	ev->path.len = bpf_probe_read_kernel_str(ev->path.buf, PATH_LEN, bprm->filename);
	bpf_ringbuf_submit(ev, 0);
	return 0;
}

/* Sleepable: reads the environment of the new process. */
SEC("lsm.s/bprm_committed_creds")
int bprm_committed_creds(u64 *ctx)
{
	struct linux_binprm *bprm = (void *)ctx[0];
	struct file_key key = file_key(bprm->file->f_inode);
	app_id *found = bpf_map_lookup_elem(&EXES, &key);
	app_id app = found ? *found : APP_UNCONFINED;
	if (app == APP_UNCONFINED && is_daemon_path(bprm))
		app = APP_DAEMON;
	struct task_struct *task = bpf_get_current_task_btf();

	/* A task of an inheriting app keeps it across an exe that is no app's
	 * (helpers, shells, a bundled runtime) and across its own: the app
	 * chose the exe, its environment and its namespace. */
	struct task_info *cur = bpf_task_storage_get(&TASKS, task, NULL, 0);
	app_id prev = cur ? cur->app_id : APP_UNCONFINED;
	if (cur && (app == APP_UNCONFINED || app == prev) && inherits(prev))
		return exec_as(bprm, key, prev);

	/* The loader would run foreign code inside the app: no identity. */
	u32 env = app != APP_UNCONFINED ? tainted_env(bprm, app) : 0;
	if (app != APP_UNCONFINED && task->cred->user_ns->level)
		env |= ENV_USERNS;
	if (env) {
		bump(STAT_ENV_DROPPED);
		/* Tainted, so seeding never gives it the identity either. */
		struct task_info *info = bpf_task_storage_get(
			&TASKS, task, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
		if (info) {
			info->app_id = APP_UNCONFINED;
			info->flags = TF_TAINTED;
		}
		struct event *ev = new_event(EV_EXEC, app, APP_UNCONFINED);
		if (!ev)
			return 0;
		ev->action = ACTION_DENY;
		ev->reason = REASON_ENV;
		ev->flags = env;
		ev->file = key;
		ev->path.kind = PATH_FULL;
		ev->path.len = bpf_probe_read_kernel_str(ev->path.buf, PATH_LEN, bprm->filename);
		bpf_ringbuf_submit(ev, 0);
		return 0;
	}

	if (app == APP_UNCONFINED) {
		int terminal = !!bpf_map_lookup_elem(&TERMINALS, &key);
		/* Unknown exe: drop any identity inherited across fork, keep
		 * the terminal flag. */
		struct task_info *info = bpf_task_storage_get(
			&TASKS, task, NULL,
			terminal ? BPF_LOCAL_STORAGE_GET_F_CREATE : 0);
		if (info) {
			info->app_id = APP_UNCONFINED;
			if (terminal)
				info->flags |= TF_TERMINAL;
		}
		return 0;
	}

	struct task_info *info = bpf_task_storage_get(
		&TASKS, task, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!info)
		return 0;
	info->app_id = app;
	/* An app between a terminal and a task ends @terminal trust. */
	info->flags = 0;
	return exec_as(bprm, key, app);
}

SEC("lsm/task_alloc")
int task_alloc(u64 *ctx)
{
	struct task_struct *child = (void *)ctx[0];
	int retval = ctx[2];
	struct task_info *parent =
		bpf_task_storage_get(&TASKS, bpf_get_current_task_btf(), NULL, 0);
	if (parent && (parent->app_id != APP_UNCONFINED || parent->flags)) {
		struct task_info copy = *parent;
		if (bpf_task_storage_get(&TASKS, child, &copy,
					 BPF_LOCAL_STORAGE_GET_F_CREATE))
			bump(STAT_FORKS);
	}
	return retval;
}

SEC("lsm/file_open")
int file_open(u64 *ctx)
{
	struct file *file = (void *)ctx[0];
	int retval = ctx[1];
	if (retval)
		return retval;

	bump(STAT_CHECKS);
	struct inode *ino = file->f_inode;
	app_id owner = owner_cached(ino, file->f_path.dentry);
	if (owner == APP_UNCONFINED)
		return 0;
	u32 flags = file->f_flags;
	u32 perms;
	if ((ino->i_mode & S_IFMT) == S_IFDIR)
		perms = PERM_LIST;
	else if ((flags & O_ACCMODE) == O_WRONLY)
		perms = PERM_WRITE;
	else if ((flags & O_ACCMODE) == O_RDWR)
		perms = PERM_READ | PERM_WRITE;
	else
		perms = PERM_READ;
	app_id subject = current_app();
	u32 lacking = missing(subject, owner, perms);
	if (!lacking)
		return 0;

	int deny = enforcing(owner);
	struct event *ev = new_event(EV_ACCESS, subject, owner);
	if (ev) {
		ev->op = OP_OPEN;
		ev->perms = lacking;
		ev->action = deny ? ACTION_DENY : ACTION_AUDIT;
		ev->flags = flags;
		ev->file = file_key(ino);
		ev->path.kind = PATH_FULL;
		ev->path.len = bpf_d_path(&file->f_path, ev->path.buf, PATH_LEN);
		bpf_ringbuf_submit(ev, 0);
	}
	if (deny) {
		bump(STAT_DENIED);
		return -EACCES;
	}
	bump(STAT_AUDITED);
	return 0;
}

/* Creating d in directory dir. */
static __always_inline int on_create(u32 op, u64 *ctx)
{
	struct inode *dir = (void *)ctx[0];
	struct dentry *d = (void *)ctx[1];
	bump(STAT_CHECKS);
	int r = exe_dir(dir, d);
	if (r)
		return r;
	return check(op, owner_in(dir, d), PERM_CREATE, 0, d);
}

/* Removing d from directory dir. */
static __always_inline int on_delete(u32 op, u64 *ctx)
{
	struct inode *dir = (void *)ctx[0];
	struct dentry *d = (void *)ctx[1];
	bump(STAT_CHECKS);
	return check(op, owner_in(dir, d), PERM_DELETE, 0, d);
}

/* A hook whose previous verdict is ctx[ret] and that is checked by fn. */
#define DIR_HOOK(name, ret, fn, op)                                            \
	SEC("lsm/" #name)                                                      \
	int name(u64 *ctx)                                                     \
	{                                                                      \
		int retval = ctx[ret];                                         \
		if (retval)                                                    \
			return retval;                                         \
		return fn(op, ctx);                                            \
	}

DIR_HOOK(inode_create, 3, on_create, OP_CREATE)
DIR_HOOK(inode_mknod, 4, on_create, OP_MKNOD)
DIR_HOOK(inode_symlink, 3, on_create, OP_SYMLINK)
DIR_HOOK(inode_unlink, 2, on_delete, OP_UNLINK)

/* inode_rmdir(dir, dentry) */
SEC("lsm/inode_rmdir")
int inode_rmdir(u64 *ctx)
{
	struct dentry *d = (void *)ctx[1];
	int retval = ctx[2];
	if (retval)
		return retval;
	int r = exe_path(d);
	if (r)
		return r;
	return on_delete(OP_RMDIR, ctx);
}

/* inode_mkdir(dir, dentry, mode). A folder an app creates right in one of
 * CLAIM_PARENTS is reported for auto-claim. */
SEC("lsm/inode_mkdir")
int inode_mkdir(u64 *ctx)
{
	struct inode *dir = (void *)ctx[0];
	struct dentry *d = (void *)ctx[1];
	int retval = ctx[3];
	if (retval)
		return retval;

	bump(STAT_CHECKS);
	int r = exe_dir(dir, d);
	if (r)
		return r;
	app_id owner = owner_in(dir, d);
	r = check(OP_MKDIR, owner, PERM_CREATE, 0, d);
	if (r || owner != APP_UNCONFINED)
		return r;
	app_id subject = current_app();
	if (subject == APP_UNCONFINED || subject == APP_AGENT)
		return 0;
	struct file_key parent = file_key(dir);
	if (!bpf_map_lookup_elem(&CLAIM_PARENTS, &parent))
		return 0;
	struct event *ev = new_event(EV_CLAIM, subject, APP_UNCONFINED);
	if (!ev)
		return 0;
	ev->file = parent;
	ev->path.kind = PATH_FULL;
	ev->path.len = bpf_probe_read_kernel_str(ev->path.buf, PATH_LEN, d->d_name.name);
	bpf_ringbuf_submit(ev, 0);
	return 0;
}

/* inode_link(old_dentry, dir, new_dentry) */
SEC("lsm/inode_link")
int inode_link(u64 *ctx)
{
	struct dentry *old = (void *)ctx[0];
	struct inode *dir = (void *)ctx[1];
	struct dentry *new = (void *)ctx[2];
	int retval = ctx[3];
	if (retval)
		return retval;

	bump(STAT_CHECKS);
	int r = exe_dir(dir, new);
	if (r)
		return r;
	app_id from = walk_owner(old);
	app_id to = owner_in(dir, new);
	if (from != to && !is_root(old))
		return cross(OP_LINK, from, to, old, new);
	app_id subject = current_app();
	u32 lacking = missing(subject, to, PERM_CREATE);
	if (lacking)
		return refuse(OP_LINK, subject, to, lacking, 0, old, new);
	return 0;
}

/* inode_rename(old_dir, old_dentry, new_dir, new_dentry). For
 * RENAME_EXCHANGE the kernel calls it twice, once in each direction. */
SEC("lsm/inode_rename")
int inode_rename(u64 *ctx)
{
	struct inode *old_dir = (void *)ctx[0];
	struct dentry *old = (void *)ctx[1];
	struct inode *new_dir = (void *)ctx[2];
	struct dentry *new = (void *)ctx[3];
	int retval = ctx[4];
	if (retval)
		return retval;

	bump(STAT_CHECKS);
	int r = exe_dir(new_dir, new);
	if (!r)
		r = exe_path(old);
	if (!r)
		r = exe_path(new);
	if (r)
		return r;
	app_id from = owner_in(old_dir, old);
	app_id to = owner_cached(new_dir, new->d_parent);
	if (from != to && !is_root(old))
		return cross(OP_RENAME, from, to, old, new);
	app_id subject = current_app();
	u32 lacking = missing(subject, from, PERM_RENAME);
	if (lacking) {
		r = refuse(OP_RENAME, subject, from, lacking, 0, old, new);
		if (r)
			return r;
	}
	/* A root moving into another owner's tree. */
	if (to != from) {
		lacking = missing(subject, to, PERM_CREATE);
		if (lacking) {
			r = refuse(OP_RENAME, subject, to, lacking, 0, old, new);
			if (r)
				return r;
		}
	}
	/* Replacing an existing target deletes it. */
	struct inode *target = new->d_inode;
	if (target) {
		app_id victim = owner_in(new_dir, new);
		lacking = missing(subject, victim, PERM_DELETE);
		if (lacking) {
			r = refuse(OP_RENAME, subject, victim, lacking, 0, old, new);
			if (r)
				return r;
		}
		/* A root replaced by a rename (an atomic save of an owned file):
		 * what takes its place is the root from now on, not only after
		 * the daemon has resolved the path again. */
		app_id *replaced = root_of(target);
		struct inode *src = old->d_inode;
		if (replaced && src && !root_of(src)) {
			struct file_key key = file_key(src);
			app_id owner = *replaced;
			if (!bpf_map_update_elem(&ROOTS, &key, &owner, BPF_ANY))
				bump_generation();
		}
	}
	return 0;
}

/* inode_setattr(idmap, dentry, attr). A size change is a write; mode, owner
 * and time changes need setattr. */
SEC("lsm/inode_setattr")
int inode_setattr(u64 *ctx)
{
	struct dentry *d = (void *)ctx[1];
	struct iattr *attr = (void *)ctx[2];
	int retval = ctx[3];
	if (retval)
		return retval;

	u32 valid = attr->ia_valid;
	u32 perms;
	/* A size change is checked even when forced: truncate(2) of a setuid
	 * file (or one with file caps) forces it to clear those bits. */
	if (valid & ATTR_SIZE)
		perms = PERM_WRITE;
	/* Kernel-internal changes, e.g. clearing setuid after a write. */
	else if (valid & ATTR_FORCE)
		return 0;
	else if (valid & ATTR_META)
		perms = PERM_SETATTR;
	else
		return 0;
	bump(STAT_CHECKS);
	return check(OP_SETATTR, walk_owner(d), perms, valid, d);
}

/* Whether the xattr name (a kernel string) is the label. */
static __always_inline int is_label(const char *name)
{
	const char label[] = LABEL_XATTR;
	char buf[sizeof(label) + 1];
	if (bpf_probe_read_kernel_str(buf, sizeof(buf), name) != sizeof(label))
		return 0;
#pragma unroll
	for (int i = 0; i < sizeof(label) - 1; i++)
		if (buf[i] != label[i])
			return 0;
	return 1;
}

/* Changing xattr name of d: only the daemon may touch the label; any other
 * xattr of protected data needs setattr. */
static __always_inline int on_xattr(u32 op, struct dentry *d, const char *name)
{
	bump(STAT_CHECKS);
	if (!is_label(name))
		return check(op, walk_owner(d), PERM_SETATTR, 0, d);
	if (current_tgid() == config(CFG_DAEMON_TGID) || current_app() == APP_DAEMON)
		return 0;
	struct event *ev = new_event(EV_ACCESS, current_app(), walk_owner(d));
	if (ev) {
		ev->op = op;
		ev->action = ACTION_DENY;
		ev->reason = REASON_LABEL;
		ev->file = dentry_key(d);
		name_chain(&ev->path, d);
		bpf_ringbuf_submit(ev, 0);
	}
	bump(STAT_DENIED);
	return -EPERM;
}

/* inode_setxattr(idmap, dentry, name, value, size, flags) */
SEC("lsm/inode_setxattr")
int inode_setxattr(u64 *ctx)
{
	int retval = ctx[6];
	if (retval)
		return retval;
	return on_xattr(OP_SETXATTR, (void *)ctx[1], (void *)ctx[2]);
}

/* inode_removexattr(idmap, dentry, name) */
SEC("lsm/inode_removexattr")
int inode_removexattr(u64 *ctx)
{
	int retval = ctx[3];
	if (retval)
		return retval;
	return on_xattr(OP_REMOVEXATTR, (void *)ctx[1], (void *)ctx[2]);
}

/* inode_set_acl(idmap, dentry, acl_name, kacl) */
SEC("lsm/inode_set_acl")
int inode_set_acl(u64 *ctx)
{
	struct dentry *d = (void *)ctx[1];
	int retval = ctx[4];
	if (retval)
		return retval;
	bump(STAT_CHECKS);
	return check(OP_SET_ACL, walk_owner(d), PERM_SETATTR, 0, d);
}

/* inode_remove_acl(idmap, dentry, acl_name) */
SEC("lsm/inode_remove_acl")
int inode_remove_acl(u64 *ctx)
{
	struct dentry *d = (void *)ctx[1];
	int retval = ctx[3];
	if (retval)
		return retval;
	bump(STAT_CHECKS);
	return check(OP_REMOVE_ACL, walk_owner(d), PERM_SETATTR, 0, d);
}

#define PTRACE_MODE_NOAUDIT 0x04
#define BPF_LINK_GET_FD_BY_ID 30

/* Whether subject may ptrace (or read the memory of) a task of target. */
static __always_inline int may_tamper(app_id subject, app_id target, u32 fsuid)
{
	if (target == APP_UNCONFINED || subject == target || subject == APP_DAEMON)
		return 1;
	return config(CFG_ROOT_BYPASS) && fsuid == 0;
}

static __always_inline app_id app_of(struct task_struct *task)
{
	struct task_info *info = bpf_task_storage_get(&TASKS, task, NULL, 0);
	return info ? info->app_id : APP_UNCONFINED;
}

/* ptrace_access_check(child, mode): ptrace attach, /proc/<pid>/mem, environ,
 * fd/, maps, process_vm_readv/writev, pidfd_getfd. */
SEC("lsm/ptrace_access_check")
int ptrace_access_check(u64 *ctx)
{
	struct task_struct *child = (void *)ctx[0];
	u32 mode = ctx[1];
	int retval = ctx[2];
	if (retval)
		return retval;
	app_id target = app_of(child);
	app_id subject = current_app();
	if (may_tamper(subject, target, current_fsuid()))
		return 0;
	return tamper(OP_PTRACE, subject, target, mode, child->tgid, NULL,
		      !(mode & PTRACE_MODE_NOAUDIT));
}

/* ptrace_traceme(parent): the current task asks parent to trace it. */
SEC("lsm/ptrace_traceme")
int ptrace_traceme(u64 *ctx)
{
	struct task_struct *parent = (void *)ctx[0];
	int retval = ctx[1];
	if (retval)
		return retval;
	app_id target = current_app();
	app_id tracer = app_of(parent);
	if (may_tamper(tracer, target, parent->cred->fsuid.val))
		return 0;
	return tamper(OP_TRACEME, tracer, target, 0, parent->tgid, NULL, 1);
}

#define SIGQUIT 3
#define SIGILL 4
#define SIGTRAP 5
#define SIGABRT 6
#define SIGBUS 7
#define SIGFPE 8
#define SIGSEGV 11
#define SIGXCPU 24
#define SIGXFSZ 25
#define SIGSYS 31

/* Whether sig's default action dumps core. */
static __always_inline int dumps_core(int sig)
{
	switch (sig) {
	case SIGQUIT:
	case SIGILL:
	case SIGTRAP:
	case SIGABRT:
	case SIGBUS:
	case SIGFPE:
	case SIGSEGV:
	case SIGXCPU:
	case SIGXFSZ:
	case SIGSYS:
		return 1;
	}
	return 0;
}

/* task_kill(p, info, sig, cred): a signal that dumps core makes the app's
 * memory readable by its user (apport, systemd-coredump). Faults the kernel
 * raises itself don't come through here. */
SEC("lsm/task_kill")
int task_kill(u64 *ctx)
{
	struct task_struct *p = (void *)ctx[0];
	int sig = ctx[2];
	int retval = ctx[4];
	if (retval)
		return retval;
	if (!dumps_core(sig))
		return 0;
	app_id target = app_of(p);
	app_id subject = current_app();
	if (may_tamper(subject, target, current_fsuid()))
		return 0;
	return tamper(OP_SIGNAL, subject, target, sig, p->tgid, NULL, 1);
}

/* task_setrlimit(p, resource, new_rlim): a low RLIMIT_CPU or RLIMIT_FSIZE
 * makes the kernel send the app a signal that dumps core. */
SEC("lsm/task_setrlimit")
int task_setrlimit(u64 *ctx)
{
	struct task_struct *p = (void *)ctx[0];
	u32 resource = ctx[1];
	int retval = ctx[3];
	if (retval)
		return retval;
	app_id target = app_of(p);
	app_id subject = current_app();
	if (may_tamper(subject, target, current_fsuid()))
		return 0;
	return tamper(OP_RLIMIT, subject, target, resource, p->tgid, NULL, 1);
}

/* A file descriptor for one of explsm's own BPF objects: only the daemon. */
static __always_inline int own_object(u32 kind, u32 id)
{
	struct own_key key = { .kind = kind, .id = id };
	if (!bpf_map_lookup_elem(&OWN_IDS, &key))
		return 0;
	app_id subject = current_app();
	if (subject == APP_DAEMON)
		return 0;
	struct event *ev = new_event(EV_ACCESS, subject, APP_DAEMON);
	if (ev) {
		ev->owner2 = id;
		ev->op = OP_BPF;
		ev->action = ACTION_DENY;
		ev->reason = REASON_SELF;
		ev->flags = kind;
		bpf_ringbuf_submit(ev, 0);
	}
	bump(STAT_DENIED);
	return -EPERM;
}

/* bpf_map(map, fmode): a new fd for a map (by id, from a pin, or created). */
SEC("lsm/bpf_map")
int bpf_map(u64 *ctx)
{
	struct bpf_map *map = (void *)ctx[0];
	int retval = ctx[2];
	if (retval)
		return retval;
	return own_object(OWN_MAP, map->id);
}

/* bpf_prog(prog): a new fd for a program. */
SEC("lsm/bpf_prog")
int bpf_prog(u64 *ctx)
{
	struct bpf_prog *prog = (void *)ctx[0];
	int retval = ctx[1];
	if (retval)
		return retval;
	return own_object(OWN_PROG, prog->aux->id);
}

/* bpf(cmd, attr, size, kernel): links have no hook of their own, so their
 * ids are checked here. attr is the kernel's copy; the id of a
 * *_GET_FD_BY_ID command is its first field (UAPI). */
SEC("lsm/bpf")
int bpf(u64 *ctx)
{
	int cmd = ctx[0];
	void *attr = (void *)ctx[1];
	int kernel = ctx[3] & 1;
	int retval = ctx[4];
	if (retval)
		return retval;
	if (kernel || cmd != BPF_LINK_GET_FD_BY_ID)
		return 0;
	u32 id = 0;
	if (bpf_probe_read_kernel(&id, sizeof(id), attr))
		return 0;
	return own_object(OWN_LINK, id);
}

/* GPL-compatible: bpf_d_path and friends are GPL-only. */
char LICENSE[] SEC("license") = "Dual MIT/GPL";
