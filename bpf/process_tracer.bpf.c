// SPDX-License-Identifier: GPL-2.0
// process_tracer.bpf.c — capture every execve with PID, PPID, comm, args
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define COMM_SIZE  16
#define ARGS_SIZE  256
#define ARG_SLOT_COUNT 5
#define ARG_SLOT_SIZE  51

/* ── event structure shared with userspace ────────────────────────── */
struct process_event {
    __u32 pid;
    __u32 ppid;
    char  comm[COMM_SIZE];
    char  args[ARGS_SIZE];
    __u64 timestamp_ns;
    __u32 is_npm_related;   // 1 if comm or args contain "npm" or "node"
    __u8  event_type;       // 0 = EXEC, 1 = FORK, 2 = EXIT
};

/* ── ring-buffer map ─────────────────────────────────────────────── */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);   /* 256 KB */
} process_events SEC(".maps");

/* ── hash map: track npm/node process tree (pid → ppid) ──────────── */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);        /* pid  */
    __type(value, __u32);      /* ppid */
    __uint(max_entries, 4096);
} tracked_pids SEC(".maps");

/* ── helper: simple in-BPF substring search ──────────────────────── */
static __always_inline int str_contains(const char *haystack, int haystack_len,
                                        const char *needle, int needle_len)
{
    for (int i = 0; i <= haystack_len - needle_len; i++) {
        int match = 1;
        for (int j = 0; j < needle_len; j++) {
            if (haystack[i + j] != needle[j]) {
                match = 0;
                break;
            }
        }
        if (match)
            return 1;
    }
    return 0;
}

static __always_inline __u32 check_npm_related(const char *comm, const char *args)
{
    /* Check comm (16 bytes max) for "npm" or "node" */
    if (str_contains(comm, COMM_SIZE, "npm",  3) ||
        str_contains(comm, COMM_SIZE, "node", 4))
        return 1;

    /* Check args (256 bytes max) for "npm" or "node" */
    if (str_contains(args, ARGS_SIZE, "npm",  3) ||
        str_contains(args, ARGS_SIZE, "node", 4))
        return 1;

    return 0;
}

/*
 * is_tracked — check whether a pid is in the tracked_pids hash map.
 *
 * Why __always_inline?  The BPF verifier in older kernels (< 4.16) does not
 * support BPF-to-BPF function calls at all; every helper must be inlined into
 * the calling program.  Even on newer kernels that do support BPF subprograms,
 * __always_inline is preferred because:
 *  1. It guarantees the verifier can trace every code path without hitting the
 *     subprogram complexity limits.
 *  2. It avoids the overhead of a BPF-to-BPF call frame (saves ~8 ns/call).
 *  3. It ensures tail-call compatibility — tail calls and BPF-to-BPF calls
 *     interact poorly on some kernel versions.
 * In short: always mark small eBPF helper functions __always_inline.
 */
static __always_inline bool is_tracked(__u32 pid)
{
    return bpf_map_lookup_elem(&tracked_pids, &pid) != NULL;
}

/* ── tracepoint: sys_enter_execve ────────────────────────────────── *
 * Tracepoint format (from /sys/kernel/tracing/events/syscalls/sys_enter_execve/format):
 *   field: const char * filename;  offset:16  size:8
 *   field: const char *const * argv; offset:24  size:8
 *   field: const char *const * envp; offset:32  size:8
 *
 * We use the generic trace_event_raw_sys_enter whose args[] array maps
 * positionally:  args[0] = filename, args[1] = argv, args[2] = envp
 */
SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct process_event *evt;

    /* Reserve space in the ring buffer */
    evt = bpf_ringbuf_reserve(&process_events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    __builtin_memset(evt, 0, sizeof(*evt));

    /* ── PID / TGID ──────────────────────────────────────────── */
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    evt->pid = (__u32)(pid_tgid >> 32);   /* tgid == userspace PID */

    /* ── PPID via current->real_parent->tgid ─────────────────── */
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    evt->ppid = BPF_CORE_READ(parent, tgid);

    /* ── comm ────────────────────────────────────────────────── */
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    /* ── timestamp ───────────────────────────────────────────── */
    evt->timestamp_ns = bpf_ktime_get_ns();

    /* ── args: capture argv[0:] into fixed slots inside evt->args. Slot 0
     * contains the executable name (for example, "npm"), and userspace
     * joins non-empty slots with spaces. Fall back to the exec filename
     * when argv is unavailable.
     */
    const char *filename = (const char *)ctx->args[0];
    const char *const *argv = (const char *const *)ctx->args[1];
    {
        int have_args = 0;

#pragma unroll
        for (int i = 0; i < ARG_SLOT_COUNT; i++) {
            const char *argp = NULL;
            const __u32 slot_offset = i * ARG_SLOT_SIZE;

            if (argv == NULL)
                break;

            if (bpf_probe_read_user(&argp, sizeof(argp), &argv[i]) < 0)
                break;

            if (argp == NULL)
                break;

            if (bpf_probe_read_user_str(evt->args + slot_offset, ARG_SLOT_SIZE, argp) <= 0)
                break;
            have_args = 1;
        }

        if (!have_args) {
            bpf_probe_read_user_str(evt->args, ARG_SLOT_SIZE, filename);
        }
    }

    /* ── npm/node classification ─────────────────────────────── */
    evt->is_npm_related = check_npm_related(evt->comm, evt->args);
    evt->event_type = 0;

    /* Inherit tracking from the parent process tree: if the parent is
     * already tracked (e.g. it was npm/node or a descendant), mark this
     * process as npm-related too so the entire subtree is captured. */
    if (!evt->is_npm_related && is_tracked(evt->ppid))
        evt->is_npm_related = 1;

    /*
     * IMPORTANT: We must submit (or discard) the ring-buffer reservation
     * BEFORE calling bpf_map_update_elem.  The verifier tracks the
     * ring-buffer slot as a reference-counted object and cannot handle a
     * second helper call (map update) that also manipulates ref_obj_id
     * while the reservation is outstanding.  Save what we need on the
     * stack, submit first, then update the map.
     */
    __u32 save_pid  = evt->pid;
    __u32 save_ppid = evt->ppid;
    __u32 save_npm  = evt->is_npm_related;

    /* Submit event to userspace — releases the ring-buffer reference */
    bpf_ringbuf_submit(evt, 0);

    /* Now safe to update the hash map (no outstanding references) */
    if (save_npm)
        bpf_map_update_elem(&tracked_pids, &save_pid, &save_ppid, BPF_ANY);

    return 0;
}

/* ── tracepoint: sched_process_fork ──────────────────────────────── *
 * Fires whenever any process calls fork/clone.  If the parent is in
 * tracked_pids we automatically add the child so the entire process
 * tree rooted at npm/node is tracked.
 *
 * Context struct (from vmlinux.h → trace_event_raw_sched_process_fork):
 *   char  parent_comm[16]
 *   pid_t parent_pid
 *   char  child_comm[16]
 *   pid_t child_pid
 */
SEC("tp/sched/sched_process_fork")
int tracepoint__sched__sched_process_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    __u32 child_pid = (__u32)ctx->child_pid;
    struct process_event *evt;

    /* tracked_pids is keyed by thread-group id everywhere else in this
     * program and in every sibling BPF file (syscall_tracer.bpf.c,
     * file_monitor.bpf.c, tcp_monitor.bpf.c all do is_tracked(tgid) with tgid
     * from bpf_get_current_pid_tgid()>>32; the exit handler below only fires
     * on tgid == tid and documents "tracked_pids stores tgids, not
     * individual thread ids").
     *
     * ctx->parent_pid is NOT that: it is the calling *task's* pid, i.e. its
     * thread id, per trace_sched_process_fork's __entry->parent_pid =
     * parent->pid in the kernel. For a single-threaded process this happens
     * to equal its tgid, so the mismatch is invisible in the common case.
     * But this tracepoint fires with current == the forking task for every
     * clone(), including one issued from a non-leader thread of a tracked
     * multithreaded process -- and a malicious install script forking from a
     * worker thread to spawn a child is exactly the kind of thing this
     * monitor exists to catch. In that case ctx->parent_pid is a tid that
     * was never inserted into tracked_pids, the lookup misses, and the fork
     * event -- and the child's whole subtree -- is silently dropped.
     *
     * bpf_get_current_pid_tgid()>>32 gives the correct tgid regardless of
     * which thread issued the syscall, matching how every other consumer of
     * this map already does the same lookup. */
    __u64 pid_tgid   = bpf_get_current_pid_tgid();
    __u32 parent_pid = (__u32)(pid_tgid >> 32);

    /* Only propagate tracking to children of already-tracked processes. */
    if (!is_tracked(parent_pid))
        return 0;

    evt = bpf_ringbuf_reserve(&process_events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    __builtin_memset(evt, 0, sizeof(*evt));
    evt->pid = child_pid;
    evt->ppid = parent_pid;
    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->is_npm_related = 1;
    evt->event_type = 1;
    /* Read comm from the current task rather than ctx->child_comm.
     *
     * This tracepoint fires inside copy_process() with current == the forking
     * task, and the child's comm is a copy of the parent's until it execs, so
     * both report the same string here.
     *
     * ctx->child_comm cannot be used portably: newer kernels declare
     * parent_comm/child_comm as __string() fields, which are stored as
     * __data_loc u32 descriptors rather than inline char[16] arrays.  CO-RE
     * cannot relocate a char[16] access onto that layout, so libbpf poisons
     * the instruction and the verifier rejects the program at load time.
     * The sibling exec and exit handlers already use this helper. */
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    __u32 save_child_pid = child_pid;
    __u32 save_parent_pid = parent_pid;

    bpf_ringbuf_submit(evt, 0);
    bpf_map_update_elem(&tracked_pids, &save_child_pid, &save_parent_pid, BPF_ANY);

    return 0;
}

/* ── tracepoint: sched_process_exit ──────────────────────────────── *
 * Fires when a task exits.  We remove the exiting pid from tracked_pids
 * to prevent the hash map from filling up over time.
 *
 * Filter: only act when the thread-group leader exits (pid == tgid),
 * because tracked_pids stores tgids, not individual thread ids.
 */
SEC("tracepoint/sched/sched_process_exit")
int tracepoint__sched__sched_process_exit(struct trace_event_raw_sched_process_template *ctx)
{
    struct process_event *evt;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid  = (__u32)pid_tgid;           /* kernel pid  (thread) */
    __u32 tgid = (__u32)(pid_tgid >> 32);   /* thread-group leader  */

    /* Only clean up when the thread-group leader exits, not every thread. */
    if (tid != tgid)
        return 0;

    if (!is_tracked(tgid))
        return 0;

    evt = bpf_ringbuf_reserve(&process_events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    __builtin_memset(evt, 0, sizeof(*evt));
    evt->pid = tgid;
    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->is_npm_related = 1;
    evt->event_type = 2;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    __u32 save_pid = evt->pid;

    bpf_ringbuf_submit(evt, 0);
    bpf_map_delete_elem(&tracked_pids, &save_pid);
    return 0;
}

char _license[] SEC("license") = "GPL";
