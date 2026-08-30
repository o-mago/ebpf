# eBPF Service Mesh Simulator

This project implements a complete, self-contained **Service Mesh** simulator powered entirely by eBPF in the Linux kernel. It showcases the three core pillars of a modern Service Mesh:

1. **Security & Traffic Control (Firewall)**: Denies socket connection attempts from unauthorized services at the system call level (`connect()`).
2. **Traffic Management (Canary Deployment)**: Dynamically routes a percentage of connections (50/50 split) from gateway to backend versions in the kernel by rewriting target ports.
3. **Observability (Tracing & Profiling)**: 
   - **Distributed Tracing**: Intercepts HTTP handlers using `uprobes` to calculate and report request latencies (spans).
   - **Resource Profiling**: Samples CPU cycle ticks (via `perf_event`) and memory heap allocations (via `runtime.mallocgc` uprobes) to measure real-time CPU % and memory allocation rates for each service.

---

## Architecture Topology

```
                  ┌──────────────────────┐
                  │   Client Requests    │
                  └──────────┬───────────┘
                             │
              ┌──────────────┴──────────────┐
              ▼                             ▼
     [Service 1 Gateway]           [Service 2 Gateway]
         (Port 8081)                   (Port 8082)
          [ALLOWED]                    [BLOCKED]
              │                             │
              ├─────────────────────────────┤ (cgroup connect4 hook)
              ▼                             ▼
      [Service 3 Stable]           [Service 3 Canary]
         (Port 8083)                   (Port 8084)
```

- **Service 1 (Gateway)**: Allowed to query Service 3.
- **Service 2 (Gateway)**: Blocked from querying Service 3 by the eBPF Firewall.
- **Service 3 Stable (v1)**: Processes HTTP requests.
- **Service 3 Canary (v2)**: Processes HTTP requests.

---

## How to Compile & Run

All commands can be run directly from the `service-mesh/` directory using **Mise**:

### 1. Build all components
```bash
mise run build
```

### 2. Start the 4 Services (Run in separate terminal tabs)
```bash
# Terminal 1: Stable Backend (v1)
mise run run:s3

# Terminal 2: Canary Backend (v2)
mise run run:s4

# Terminal 3: Allowed Gateway (S1)
mise run run:s1

# Terminal 4: Blocked Gateway (S2)
mise run run:s2
```

### 3. Start the eBPF Service Mesh Control Panel
In another terminal, run:
```bash
mise run run:control-panel
```
*(This starts the live dashboard console. It automatically scans service PIDs, attaches the cgroup filters, sets up uprobes/perf events, and begins monitoring.)*

---

## How to Test

### Option A: Using the HTTP request file
Use the provided [api.http](file:///Users/mago/dev/ebpf/service-mesh/api.http) file with REST Client extensions to fire requests with a single click.

### Option B: Using curl
Send requests to the gateways:

```bash
# Test Service 1 (Allowed + Canary Split)
# Send multiple requests to see the 50/50 routing split and live CPU/Memory profiling spikes
for i in {1..20}; do curl -s http://localhost:8081/api/work > /dev/null; done

# Test Service 2 (Blocked by Firewall)
# Fails immediately with HTTP 502 (connect: operation not permitted)
curl -i http://localhost:8082/api/work
```
