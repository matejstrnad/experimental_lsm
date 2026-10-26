/* Types and constants shared with userspace. Mirrors explsm-common/src/lib.rs,
 * which documents them; both sides assert the same sizes and offsets.
 */
#ifndef EXPLSM_H
#define EXPLSM_H

#include "vmlinux.h"

typedef u32 app_id;

#define APP_UNCONFINED 0
#define OWNER_ANY 0xffffffffu
#define MAX_APPS 256
#define APP_AGENT (MAX_APPS - 1)
#define APP_DAEMON (MAX_APPS - 2)
#define OWNER_PINS (MAX_APPS - 3)
/* Set in a ROOTS value: the entry is a user-writable app exe, which anyone
 * may read (and so run) but only its app may change. */
#define OWNER_EXE 0x80000000u
#define SUBJECT_TERMINAL 0xfffffffeu
#define TF_TERMINAL 1
#define TF_TAINTED 2
#define MAX_WALK 64
#define PATH_LEN 512
#define MAX_CHAIN 16
#define LABEL_XATTR "security.bpf.explsm"

#define PERM_READ (1 << 0)
#define PERM_WRITE (1 << 1)
#define PERM_CREATE (1 << 2)
#define PERM_DELETE (1 << 3)
#define PERM_RENAME (1 << 4)
#define PERM_LIST (1 << 5)
#define PERM_SETATTR (1 << 6)

#define MODE_AUDIT 0
#define MODE_ENFORCE 1

/* APP_FLAGS bits. */
#define AF_INHERIT 1

#define CFG_GENERATION 0
#define CFG_ROOT_BYPASS 1
#define CFG_DAEMON_TGID 2
#define CFG_LAYOUT 3
#define CFG_LOG_EXECS 4
#define CONFIG_LEN 5

enum stat {
	STAT_CHECKS,
	STAT_CACHE_HITS,
	STAT_CACHE_MISSES,
	STAT_WALK_EXHAUSTED,
	STAT_FOREIGN,
	STAT_AUDITED,
	STAT_DENIED,
	STAT_EXECS,
	STAT_FORKS,
	STAT_DROPPED,
	STAT_ENV_DROPPED,
	STAT_TAMPER,
	STATS_LEN,
};

enum event_kind {
	EV_EXEC = 1,
	EV_ACCESS = 2,
	EV_CLAIM = 3,
};

enum op {
	OP_OPEN = 1,
	OP_CREATE,
	OP_MKDIR,
	OP_MKNOD,
	OP_SYMLINK,
	OP_LINK,
	OP_UNLINK,
	OP_RMDIR,
	OP_RENAME,
	OP_SETATTR,
	OP_SETXATTR,
	OP_REMOVEXATTR,
	OP_SET_ACL,
	OP_REMOVE_ACL,
	OP_PTRACE,
	OP_TRACEME,
	OP_EXE_DIR,
	OP_BPF,
	OP_SIGNAL,
	OP_RLIMIT,
};

#define ACTION_AUDIT 0
#define ACTION_DENY 1

#define REASON_PERMS 0
#define REASON_CROSS 1
#define REASON_LABEL 2
#define REASON_TAMPER 3
#define REASON_ENV 4
#define REASON_SELF 5

#define ENV_LD_PRELOAD (1 << 0)
#define ENV_LD_LIBRARY_PATH (1 << 1)
#define ENV_LD_AUDIT (1 << 2)
#define ENV_UNREADABLE (1 << 3)
#define ENV_USERNS (1 << 4)

#define OWN_MAP 1
#define OWN_PROG 2
#define OWN_LINK 3

#define PATH_NONE 0
#define PATH_FULL 1
#define PATH_CHAIN 2
#define PATH_CHAIN_COMPLETE 3

struct file_key {
	u32 dev;
	u32 _pad;
	u64 ino;
};

struct task_info {
	app_id app_id;
	u32 flags;
};

#define TK_PROC 1
#define TK_APP 2
#define TK_EXE 3

struct temp_key {
	u32 kind;
	u32 uid;
	app_id owner;
	u32 _pad;
	u64 a;
	u64 b;
};

struct own_key {
	u32 kind;
	u32 id;
};

/* The daemon's install path, NUL-terminated (DAEMON_PATH). */
#define DAEMON_PATH_LEN 256
struct daemon_path {
	char path[DAEMON_PATH_LEN];
};

/* Bytes of the exec strings read at a time, and the most an ALLOWED_ENV
 * string may have with its NUL. */
#define ENV_CHUNK 128
/* Key of ALLOWED_ENV: a loader variable as "NAME=VALUE", NUL-padded. */
struct env_key {
	app_id app;
	char val[ENV_CHUNK];
};

struct inode_cache {
	app_id owner;
	u32 generation;
};

struct grant_key {
	app_id subject;
	app_id owner;
};

struct ev_path {
	u32 kind;
	s32 len;
	char buf[PATH_LEN];
};

struct event {
	u32 kind;
	u32 pid;
	u32 tid;
	u32 uid;
	app_id subject;
	app_id owner;
	app_id owner2;
	u32 op;
	u32 perms;
	u32 action;
	u32 reason;
	u32 flags;
	struct file_key file;
	char comm[16];
	char proc_comm[16];
	struct ev_path path;
	struct ev_path path2;
	struct file_key exe;
	u32 task_flags;
	u32 _pad;
	u64 start_time;
};

_Static_assert(sizeof(struct file_key) == 16, "file_key layout");
_Static_assert(sizeof(struct ev_path) == 520, "ev_path layout");
_Static_assert(__builtin_offsetof(struct event, file) == 48, "event layout");
_Static_assert(__builtin_offsetof(struct event, path) == 96, "event layout");
_Static_assert(__builtin_offsetof(struct event, path2) == 616, "event layout");
_Static_assert(__builtin_offsetof(struct event, exe) == 1136, "event layout");
_Static_assert(__builtin_offsetof(struct event, start_time) == 1160, "event layout");
_Static_assert(sizeof(struct event) == 1168, "event layout");
_Static_assert(sizeof(struct temp_key) == 32, "temp_key layout");
_Static_assert(sizeof(struct env_key) == 132, "env_key layout");

#endif
