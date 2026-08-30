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
#define GET_SIZE(x) ((x)->ax)

#elif defined(__TARGET_ARCH_arm64)
struct pt_regs {
    unsigned long regs[31];
    unsigned long sp;
    unsigned long pc;
    unsigned long pstate;
};
#define GET_SIZE(x) ((x)->regs[0])

#else
#define GET_SIZE(x) 0
#endif

struct alloc_metrics {
    __u64 total_bytes;
    __u64 alloc_count;
};

struct stack_alloc {
    __u64 bytes;
    __u64 count;
};

// Global read-only config variable rewritten at load time by user space Go
const volatile __u32 target_pid = 0;

// Map for counting CPU clock samples inside the target PID
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} cpu_samples SEC(".maps");

// Map for counting heap allocations inside the target PID
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct alloc_metrics);
} mem_metrics SEC(".maps");

// Map to store instruction pointers for stack traces
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 1024);
    __uint(key_size, sizeof(__s32));
    __uint(value_size, 20 * sizeof(__u64)); // Up to 20 frames
} stack_traces SEC(".maps");

// Hash map to associate Stack ID with allocation metrics
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __s32);
    __type(value, struct stack_alloc);
} stack_allocs SEC(".maps");

// Hash map to associate Stack ID with CPU sample counts
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __s32);
    __type(value, __u64); // CPU sample count
} cpu_stack_samples SEC(".maps");

SEC("perf_event")
int do_cpu_sample(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;

    if (tgid == target_pid) {
        // Update overall CPU samples
        __u32 key = 0;
        __u64 *count = bpf_map_lookup_elem(&cpu_samples, &key);
        if (count) {
            __sync_fetch_and_add(count, 1);
        }

        // Capture user space stack trace
        __s32 stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
        if (stack_id >= 0) {
            __u64 *stack_count = bpf_map_lookup_elem(&cpu_stack_samples, &stack_id);
            if (stack_count) {
                __sync_fetch_and_add(stack_count, 1);
            } else {
                __u64 init_count = 1;
                bpf_map_update_elem(&cpu_stack_samples, &stack_id, &init_count, BPF_ANY);
            }
        }
    }
    return 0;
}

SEC("uprobe/runtime.mallocgc")
int trace_malloc(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;

    if (tgid == target_pid) {
        __u64 size = GET_SIZE(ctx);

        // Update overall memory metrics
        __u32 key = 0;
        struct alloc_metrics *metrics = bpf_map_lookup_elem(&mem_metrics, &key);
        if (metrics) {
            __sync_fetch_and_add(&metrics->total_bytes, size);
            __sync_fetch_and_add(&metrics->alloc_count, 1);
        }

        // Capture user space stack trace
        __s32 stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
        if (stack_id >= 0) {
            struct stack_alloc *sa = bpf_map_lookup_elem(&stack_allocs, &stack_id);
            if (sa) {
                __sync_fetch_and_add(&sa->bytes, size);
                __sync_fetch_and_add(&sa->count, 1);
            } else {
                struct stack_alloc new_sa = {};
                new_sa.bytes = size;
                new_sa.count = 1;
                bpf_map_update_elem(&stack_allocs, &stack_id, &new_sa, BPF_ANY);
            }
        }
    }
    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
