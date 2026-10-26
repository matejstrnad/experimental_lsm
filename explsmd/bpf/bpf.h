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

enum {
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
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
