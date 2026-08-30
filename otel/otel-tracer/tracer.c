//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#if defined(__TARGET_ARCH_x86)
struct pt_regs {
    unsigned long r15;
    unsigned long r14;
    unsigned long r13;
    unsigned long r12;
    unsigned long bp;
    unsigned long bx;
    unsigned long r11;
    unsigned long r10;
    unsigned long r9;
    unsigned long r8;
    unsigned long ax;
    unsigned long cx;
    unsigned long dx;
    unsigned long si;
    unsigned long di;
    unsigned long orig_ax;
    unsigned long ip;
    unsigned long cs;
    unsigned long flags;
    unsigned long sp;
    unsigned long ss;
};
// For handleHealth(w, r) and handleWork(w, r) where w is http.ResponseWriter interface:
// First word (itab) is in RAX, Second word (concrete response pointer) is in RBX.
#define GET_CONN_PTR_ENTRY(x) ((x)->bx)

// For finishRequest(w *response) receiver:
// Concrete receiver pointer is in RAX.
#define GET_CONN_PTR_EXIT(x) ((x)->ax)

#elif defined(__TARGET_ARCH_arm64)
struct pt_regs {
    unsigned long regs[31];
    unsigned long sp;
    unsigned long pc;
    unsigned long pstate;
};
// First word (itab) is in R0, Second word (concrete response pointer) is in R1.
#define GET_CONN_PTR_ENTRY(x) ((x)->regs[1])

// Concrete receiver pointer is in R0.
#define GET_CONN_PTR_EXIT(x) ((x)->regs[0])

#else
#define GET_CONN_PTR_ENTRY(x) 0
#define GET_CONN_PTR_EXIT(x) 0
#endif

struct span_event {
    __u32 route_id;
    __u32 padding;
    __u64 duration_ns;
    __u64 timestamp_ns;
};

struct request_info {
    __u64 start_ns;
    __u32 route_id;
    __u32 padding;
};

// Map to store request info keyed by response pointer (w)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64); // key is response struct pointer
    __type(value, struct request_info);
} active_requests SEC(".maps");

// Ring buffer to send events to user-space
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096 * 4); // 16KB
} events SEC(".maps");

static __always_inline int trace_entry(struct pt_regs *ctx, __u32 route_id) {
    __u64 conn_ptr = GET_CONN_PTR_ENTRY(ctx);
    if (!conn_ptr) {
        return 0;
    }

    struct request_info info = {};
    info.start_ns = bpf_ktime_get_ns();
    info.route_id = route_id;

    bpf_map_update_elem(&active_requests, &conn_ptr, &info, BPF_ANY);
    return 0;
}

SEC("uprobe/handleHealth")
int trace_health_entry(struct pt_regs *ctx) {
    return trace_entry(ctx, 1);
}

SEC("uprobe/handleWork")
int trace_work_entry(struct pt_regs *ctx) {
    return trace_entry(ctx, 2);
}

SEC("uprobe/finishRequest")
int trace_finish_request(struct pt_regs *ctx) {
    __u64 conn_ptr = GET_CONN_PTR_EXIT(ctx);
    if (!conn_ptr) {
        return 0;
    }

    struct request_info *info = bpf_map_lookup_elem(&active_requests, &conn_ptr);
    if (!info) {
        return 0;
    }

    __u64 duration_ns = bpf_ktime_get_ns() - info->start_ns;
    __u32 route_id = info->route_id;
    bpf_map_delete_elem(&active_requests, &conn_ptr);

    struct span_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->route_id = route_id;
    e->duration_ns = duration_ns;
    e->timestamp_ns = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
