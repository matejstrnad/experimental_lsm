/* The few pieces of libbpf's bpf_helpers.h that explsm.bpf.c needs, so the
 * build only needs clang. Helper numbers are stable kernel UAPI
 * (enum bpf_func_id in include/uapi/linux/bpf.h).
 */
#ifndef EXPLSM_BPF_H
#define EXPLSM_BPF_H

#include "vmlinux.h"

#define SEC(name) __attribute__((section(name), used))
#define __always_inline inline __attribute__((always_inline))

/* BTF map definitions, as libbpf and Aya parse them. */
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

#define NULL ((void *)0)

/* Whether the running kernel's struct has the field (a CO-RE relocation,
 * BPF_FIELD_EXISTS): a field it lacks is read in a branch the verifier
 * knows is never taken. */
#define bpf_core_field_exists(field) __builtin_preserve_field_info(field, 2)

/* Typed hook arguments, like libbpf's BPF_PROG:
 *
 *	SEC("lsm/file_open")
 *	int LSM_PROG(file_open, struct file *file, int ret) { ... }
 *
 * defines file_open(u64 *ctx), which calls the body with ctx[0], ctx[1].
 * The arguments must be the hook's, in its order, then the previous LSM's
 * verdict; the daemon checks them against the kernel's BTF before loading
 * (explsmd/src/hooks.rs). Scalars are truncated to the declared type. */
#define ___concat(a, b) a##b
#define ___apply(fn, n) ___concat(fn, n)
#define ___nth(_, _1, _2, _3, _4, _5, _6, _7, _8, N, ...) N
#define ___narg(...) ___nth(_, ##__VA_ARGS__, 8, 7, 6, 5, 4, 3, 2, 1, 0)
#define ___ctx1(x) (void *)ctx[0]
#define ___ctx2(x, args...) ___ctx1(args), (void *)ctx[1]
#define ___ctx3(x, args...) ___ctx2(args), (void *)ctx[2]
#define ___ctx4(x, args...) ___ctx3(args), (void *)ctx[3]
#define ___ctx5(x, args...) ___ctx4(args), (void *)ctx[4]
#define ___ctx6(x, args...) ___ctx5(args), (void *)ctx[5]
#define ___ctx7(x, args...) ___ctx6(args), (void *)ctx[6]
#define ___ctx8(x, args...) ___ctx7(args), (void *)ctx[7]
#define LSM_PROG(name, args...)                                                \
	name(u64 *ctx);                                                        \
	static __always_inline int ____##name(u64 *ctx, ##args);               \
	int name(u64 *ctx)                                                     \
	{                                                                      \
		_Pragma("GCC diagnostic push")                                 \
		_Pragma("GCC diagnostic ignored \"-Wint-conversion\"")         \
		return ____##name(ctx, ___apply(___ctx, ___narg(args))(args)); \
		_Pragma("GCC diagnostic pop")                                  \
	}                                                                      \
	static __always_inline int ____##name(u64 *ctx, ##args)

enum {
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_LPM_TRIE = 11,
	BPF_MAP_TYPE_RINGBUF = 27,
	BPF_MAP_TYPE_INODE_STORAGE = 28,
	BPF_MAP_TYPE_TASK_STORAGE = 29,
};

#define BPF_F_NO_PREALLOC 1
#define BPF_ANY 0
#define BPF_LOCAL_STORAGE_GET_F_CREATE 1
#define LIBBPF_PIN_BY_NAME 1

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, u64 flags) = (void *)2;
static u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static u64 (*bpf_get_current_uid_gid)(void) = (void *)15;
static long (*bpf_get_current_comm)(void *buf, u32 size) = (void *)16;
static long (*bpf_probe_read_user)(void *dst, u32 size, const void *src) = (void *)112;
static long (*bpf_probe_read_user_str)(void *dst, u32 size, const void *src) = (void *)114;
static long (*bpf_probe_read_kernel)(void *dst, u32 size, const void *src) = (void *)113;
static long (*bpf_probe_read_kernel_str)(void *dst, u32 size, const void *src) = (void *)115;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, u64 size, u64 flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, u64 flags) = (void *)132;
static void *(*bpf_inode_storage_get)(void *map, void *inode, void *value, u64 flags) = (void *)145;
static long (*bpf_d_path)(struct path *path, char *buf, u32 sz) = (void *)147;
static void *(*bpf_task_storage_get)(void *map, struct task_struct *task, void *value, u64 flags) = (void *)156;
static struct task_struct *(*bpf_get_current_task_btf)(void) = (void *)158;
static long (*bpf_loop)(u32 nr_loops, void *callback_fn, void *callback_ctx, u64 flags) = (void *)181;

#endif
