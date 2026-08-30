//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

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
#define GET_SIZE(x) ((x)->ax)
#define GET_CONN_PTR_ENTRY(x) ((x)->bx)
#define GET_CONN_PTR_EXIT(x) ((x)->ax)

#elif defined(__TARGET_ARCH_arm64)
struct pt_regs {
    unsigned long regs[31];
    unsigned long sp;
    unsigned long pc;
    unsigned long pstate;
};
#define GET_SIZE(x) ((x)->regs[0])
#define GET_CONN_PTR_ENTRY(x) ((x)->regs[1])
#define GET_CONN_PTR_EXIT(x) ((x)->regs[0])

#else
#define GET_SIZE(x) 0
#define GET_CONN_PTR_ENTRY(x) 0
#define GET_CONN_PTR_EXIT(x) 0
#endif

// Event structure representing different audits sent to user-space
struct mesh_event {
    __u64 duration_ns;// Latency (for Spans)
    __u32 type;       // 1 = Span, 2 = Firewall, 3 = Canary Redirect
    __u32 pid;        // Caller process PID
    __u32 action;     // 0 = Block, 1 = Allow, 2 = Redirected
    __u32 dst_ip;     // Destination IP
    __u32 dst_port;   // Destination Port
    __u32 route_id;   // 1 = /health, 2 = /api/work (for Spans)
};

struct request_info {
    __u64 start_ns;
    __u32 route_id;
    __u32 padding;
};

struct alloc_metrics {
    __u64 total_bytes;
    __u64 alloc_count;
};

// Map to store blocked PIDs (firewall)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u32);
} blocked_pids SEC(".maps");

// Map to store profiled PIDs (CPU / Memory)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u32); // just active flag
} profiled_pids SEC(".maps");

// Map to restrict trace spans to backend processes (Service 3 and 4)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u32);
} backend_pids SEC(".maps");

// Map to store CPU ticks aggregated by PID
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} cpu_samples SEC(".maps");

// Map to store memory heap allocation metrics aggregated by PID
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, struct alloc_metrics);
} service_metrics SEC(".maps");

// Map to correlate request trace spans keyed by response pointer (w)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct request_info);
} active_requests SEC(".maps");

// Ring buffer to publish logs and spans to user-space
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096 * 8); // 32KB
} events SEC(".maps");

// eBPF Firewall + Canary Redirection at socket layer
SEC("cgroup/connect4")
int check_connect(struct bpf_sock_addr *ctx) {
    // Port 8083 is Service 3 Stable
    if (ctx->user_port == bpf_htons(8083)) {
        __u64 pid_tgid = bpf_get_current_pid_tgid();
        __u32 pid = pid_tgid >> 32;

        // Check if the calling PID is blocked by firewall rules
        __u32 *blocked = bpf_map_lookup_elem(&blocked_pids, &pid);
        if (blocked) {
            // Publish Block event
            struct mesh_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
            if (e) {
                e->type = 2; // Firewall event
                e->pid = pid;
                e->action = 0; // Block/Deny
                e->dst_ip = ctx->user_ip4;
                e->dst_port = bpf_ntohs(ctx->user_port);
                e->duration_ns = 0;
                e->route_id = 0;
                bpf_ringbuf_submit(e, 0);
            }
            return 0; // Block socket connect!
        }

        // Canary routing policy: Redirect 50% of traffic to port 8084 (Canary)
        __u32 rand_val = bpf_get_prandom_u32();
        if (rand_val % 2 == 0) {
            // Publish Redirect event
            struct mesh_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
            if (e) {
                e->type = 3; // Routing event
                e->pid = pid;
                e->action = 2; // Redirected
                e->dst_ip = ctx->user_ip4;
                e->dst_port = 8084;
                e->duration_ns = 0;
                e->route_id = 0;
                bpf_ringbuf_submit(e, 0);
            }
            // Rewrite destination port to 8084 in socket connect parameters
            ctx->user_port = bpf_htons(8084);
        } else {
            // Publish Allow event
            struct mesh_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
            if (e) {
                e->type = 2; // Firewall event
                e->pid = pid;
                e->action = 1; // Allowed
                e->dst_ip = ctx->user_ip4;
                e->dst_port = bpf_ntohs(ctx->user_port);
                e->duration_ns = 0;
                e->route_id = 0;
                bpf_ringbuf_submit(e, 0);
            }
        }
    }
    return 1; // Allow connection
}

// Helper to register span start time
static __always_inline int trace_entry(struct pt_regs *ctx, __u32 route_id) {
    __u64 conn_ptr = GET_CONN_PTR_ENTRY(ctx);
    if (!conn_ptr) {
        return 0;
    }

    struct request_info info = {};
    info.start_ns = bpf_ktime_get_ns();
    info.route_id = route_id;

    bpf_printk("trace_entry: route=%d conn_ptr=%llx", route_id, conn_ptr);

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

// Latency distributed tracing span publish
SEC("uprobe/finishRequest")
int trace_finish_request(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    // Filter out non-backend processes (e.g. Gateway Service 1 & 2)
    __u32 *is_backend = bpf_map_lookup_elem(&backend_pids, &pid);
    if (!is_backend) {
        return 0;
    }

    __u64 conn_ptr = GET_CONN_PTR_EXIT(ctx);
    if (!conn_ptr) {
        return 0;
    }

    bpf_printk("trace_finish: conn_ptr=%llx pid=%d", conn_ptr, pid);

    struct request_info *info = bpf_map_lookup_elem(&active_requests, &conn_ptr);
    if (!info) {
        bpf_printk("trace_finish: MISSED! conn_ptr=%llx", conn_ptr);
        return 0;
    }

    __u64 duration_ns = bpf_ktime_get_ns() - info->start_ns;
    __u32 route_id = info->route_id;
    bpf_map_delete_elem(&active_requests, &conn_ptr);

    bpf_printk("trace_finish: MATCH! route=%d duration=%llu", route_id, duration_ns);

    // Publish Span event
    struct mesh_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->type = 1; // Span event
        e->pid = pid;
        e->action = 1;
        e->dst_ip = 0;
        e->dst_port = 0;
        e->duration_ns = duration_ns;
        e->route_id = route_id;
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}

// Memory profiling: Hook Go runtime memory allocations
SEC("uprobe/runtime.mallocgc")
int trace_malloc(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    // Check if this process belongs to our service mesh profile list
    __u32 *active = bpf_map_lookup_elem(&profiled_pids, &pid);
    if (active) {
        __u64 size = GET_SIZE(ctx);

        struct alloc_metrics *metrics = bpf_map_lookup_elem(&service_metrics, &pid);
        if (metrics) {
            __sync_fetch_and_add(&metrics->total_bytes, size);
            __sync_fetch_and_add(&metrics->alloc_count, 1);
        } else {
            struct alloc_metrics new_metrics = {};
            new_metrics.total_bytes = size;
            new_metrics.alloc_count = 1;
            bpf_map_update_elem(&service_metrics, &pid, &new_metrics, BPF_ANY);
        }
    }
    return 0;
}

// CPU profiling: CPU cycle clock interrupt sampling
SEC("perf_event")
int do_cpu_sample(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    // Increment CPU cycle tick count if process is in the profiled PIDs list
    __u32 *active = bpf_map_lookup_elem(&profiled_pids, &pid);
    if (active) {
        __u64 *count = bpf_map_lookup_elem(&cpu_samples, &pid);
        if (count) {
            __sync_fetch_and_add(count, 1);
        } else {
            __u64 init_count = 1;
            bpf_map_update_elem(&cpu_samples, &pid, &init_count, BPF_ANY);
        }
    }
    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
