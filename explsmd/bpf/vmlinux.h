/* Kernel types used by explsm.bpf.c: only the fields that are read.
 *
 * Every struct is marked preserve_access_index, so clang records a CO-RE
 * relocation for each field access and the loader fixes up offsets against
 * the running kernel's BTF. Fields are matched by name, also through
 * anonymous unions, so the layout here doesn't have to match any kernel.
 */
#ifndef EXPLSM_VMLINUX_H
#define EXPLSM_VMLINUX_H

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef int s32;
typedef long long s64;

typedef u32 dev_t;
typedef u16 umode_t;
typedef u32 uid_t;

typedef struct {
	uid_t val;
} kuid_t;

#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)

struct user_namespace {
	/* 0 for the initial user namespace. */
	int level;
};

struct cred {
	kuid_t euid;
	kuid_t fsuid;
	struct user_namespace *user_ns;
};

struct tty_struct;

struct signal_struct {
	struct tty_struct *tty;
};

struct mm_struct {
	struct file *exe_file;
};

struct task_struct {
	const struct cred *cred;
	struct mm_struct *mm;
	struct signal_struct *signal;
	struct task_struct *group_leader;
	int tgid;
	char comm[16];
	u64 start_boottime;
};

struct super_block {
	dev_t s_dev;
};

struct inode {
	umode_t i_mode;
	unsigned long i_ino;
	struct super_block *i_sb;
};

struct qstr {
	const unsigned char *name;
};

struct dentry {
	struct dentry *d_parent;
	struct qstr d_name;
	struct inode *d_inode;
	struct super_block *d_sb;
};

struct path {
	struct dentry *dentry;
};

struct file {
	struct path f_path;
	struct inode *f_inode;
	unsigned int f_flags;
};

struct linux_binprm {
	unsigned long p;
	struct file *file;
	int argc;
	int envc;
	const char *filename;
	unsigned long exec;
};

struct bpf_map {
	u32 id;
};

struct bpf_prog_aux {
	u32 id;
};

struct bpf_prog {
	struct bpf_prog_aux *aux;
};

struct iattr {
	unsigned int ia_valid;
};

#pragma clang attribute pop

#endif
