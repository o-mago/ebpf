# eBPF cgroup Network Policy Firewall Simulator

This project simulates a network policy firewall filter using eBPF cgroups. It allows you to block TCP connections between specific microservices dynamically at the kernel system call level.

## Architecture

We have 3 microservices communicating over HTTP/TCP:
- **Service 1 (Port 8081)**: Makes an HTTP request to Service 3 (allowed).
- **Service 2 (Port 8082)**: Makes an HTTP request to Service 3 (blocked).
- **Service 3 (Port 8083)**: The receiver service.

### How the eBPF Firewall Works
The eBPF controller (`ebpf-mesh`) attaches a `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` program to the root cgroup v2 (`/sys/fs/cgroup`).
1. Every time a process calls the `connect()` system call to initiate a TCP connection:
   - The eBPF program hooks `cgroup/connect4`.
   - It intercepts the socket context, checking if the destination port is `8083` (Service 3).
   - If it matches port `8083`, it queries the blocked PIDs map (`blocked_pids`) for the PID of the calling process (`bpf_get_current_pid_tgid()`).
   - If the calling PID is blocked, it returns `0` (denying the connection).
   - Otherwise, it returns `1` (allowing the connection).
2. The blocked process gets a **`connect: operation not permitted`** (`EPERM`) error immediately from the kernel socket connection attempt, preventing any network packet from being sent.

---

## How to Compile & Run

All commands can be run directly from the `ebpf-firewall/` directory using **Mise**:

### 1. Build all components
```bash
mise run build
```

### 2. Start the 3 Services (Run in separate terminal tabs)
```bash
# Terminal 1: Start Service 3
mise run run:s3

# Terminal 2: Start Service 1
mise run run:s1

# Terminal 3: Start Service 2
mise run run:s2
```

### 3. Start the eBPF Firewall
In another terminal, run:
```bash
mise run run:firewall
```
*(This task automatically retrieves the PID of `service 2` inside the VM and registers it in the eBPF block list.)*

---

## How to Test

### Option A: Using curl
Send requests to Service 1 and Service 2 to make them call Service 3:

```bash
# Test Service 1 (Allowed)
# Returns: HTTP 200 OK
curl -i http://localhost:8081/call

# Test Service 2 (Blocked)
# Returns: HTTP 502 Bad Gateway
# Payload: connect: operation not permitted
curl -i http://localhost:8082/call
```

### Option B: Using the HTTP request file
You can also use the provided [api.http](file:///Users/mago/dev/ebpf/ebpf-firewall/api.http) file with tools like the VSCode REST Client extension to execute the requests with a single click.
