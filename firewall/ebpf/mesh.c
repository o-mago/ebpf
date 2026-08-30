//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct firewall_event {
    __u32 pid;
    __u32 action; // 0 for Block, 1 for Allow
    __u32 dst_ip;
    __u32 dst_port;
};

// Map to store blocked PIDs
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
} blocked_pids SEC(".maps");

// Ring buffer to send events to user-space
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096 * 4); // 16KB
} events SEC(".maps");

SEC("cgroup/connect4")
int check_connect(struct bpf_sock_addr *ctx) {
    // Port 8083 in big-endian (network byte order)
    if (ctx->user_port == bpf_htons(8083)) {
        __u64 pid_tgid = bpf_get_current_pid_tgid();
        __u32 pid = pid_tgid >> 32;
        __u32 action = 1; // Default is ALLOW

        __u32 *blocked = bpf_map_lookup_elem(&blocked_pids, &pid);
        if (blocked) {
            action = 0; // BLOCK
        }

        // Submit event to user-space Ring Buffer
        struct firewall_event *e;
        e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->pid = pid;
            e->action = action;
            e->dst_ip = ctx->user_ip4;
            e->dst_port = bpf_ntohs(ctx->user_port);
            bpf_ringbuf_submit(e, 0);
        }

        if (action == 0) {
            return 0; // Deny connection
        }
    }
    // Allow connection
    return 1;
}

char __license[] SEC("license") = "Dual MIT/GPL";
