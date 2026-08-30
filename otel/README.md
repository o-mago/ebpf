# eBPF OpenTelemetry Auto-Instrumentation & Profiling Simulator

This project demonstrates a real-world **eBPF Auto-Instrumentation and Profiling** scenario. It consists of decoupled applications:

1. **Target API Server (`api-server`)**: A completely clean Go HTTP server with **zero** eBPF or OpenTelemetry code. It knows nothing about tracing or profiling.
2. **eBPF Tracer (`otel-tracer`)**: An external monitoring tool that loads an eBPF program, attaches uprobes dynamically, measures response latencies, and prints simulated OpenTelemetry spans to the console.
3. **eBPF Profiler (`otel-profiler`)**: An external agent that uses eBPF to profile CPU utilization (via periodic CPU clock sampling) and Memory Heap allocations (via a uprobe on the Go runtime's memory allocator `runtime.mallocgc`), printing simulated OTel Profiles to the console.

---

## Architecture

### 1. Target API Server (`api-server/`)
- Independent Go module with its own [go.mod](file:///Users/mago/dev/ebpf/otel-simulation/api-server/go.mod).
- Exposes `GET /health` and `GET /api/work`.
- Employs `//go:noinline` to ensure handlers are not optimized away by the Go compiler, keeping their symbol names in the binary.
- Simulates work via a CPU busy-loop so that the OS thread is not yielded (making thread-id based correlation simple and reliable).
- Contains the [api.http](file:///Users/mago/dev/ebpf/otel-simulation/api-server/api.http) simulation file.

### 2. eBPF Tracer (`otel-tracer/`)
- Independent Go module with its own [go.mod](file:///Users/mago/dev/ebpf/otel-simulation/otel-tracer/go.mod).
- **Uprobe (Handler Entry)**: Intercepts the entry of `handleHealth` and `handleWork`, saving the monotonic kernel start timestamp in a BPF Hash Map, keyed by the thread ID (`bpf_get_current_pid_tgid()`).
- **Uprobe (Request finish)**: Intercepts the entry of `net/http.(*response).finishRequest`, fetches the start timestamp, calculates the duration, deletes the map entry, and pushes a `span_event` to the eBPF Ring Buffer.
- **Tracer Daemon**: Reads the events from the Ring Buffer, generates simulated trace/span IDs, and outputs them to the console.

### 3. eBPF Profiler (`otel-profiler/`)
- Independent Go module with its own [go.mod](file:///Users/mago/dev/ebpf/otel-simulation/otel-profiler/go.mod).
- **CPU Profiler (Perf Event)**: Configures a `PERF_COUNT_SW_CPU_CLOCK` perf event firing at **99Hz** on all online CPU cores. The eBPF program filters by the target process's PID (`target_pid` global constant rewritten at load time) and increments a sample counter in an eBPF Array Map.
- **Memory Profiler (Uprobe)**: Hooks `runtime.mallocgc` (the Go runtime's allocator function) in the target binary. On invocation, it extracts the requested allocation size from the registers (architecture-independent using macros) and aggregates the total bytes allocated and number of allocations in an eBPF Array Map.
- **Profiler Daemon**: Periodically reads the CPU sample count and Memory allocation metrics, calculates differentials, approximates CPU utilization, and prints simulated OTel Profile stats.

---

## How to Compile & Run

You can build and run using **Mise** from the root of `otel-simulation`, or using standard Go commands manually inside each subfolder.

### Option A: Using Mise (Recommended)

1. **Build all applications:**
   Run from the `otel-simulation/` root:
   ```bash
   mise run build
   ```
   *This automatically triggers eBPF Go bindings generation for both tracer and profiler, and compiles all three binaries to their respective `bin/` directories.*

2. **Run the API server:**
   Run from the `otel-simulation/` root:
   ```bash
   mise run run:api
   ```

3. **Run the Tracer (requires sudo):**
   Run from the `otel-simulation/` root:
   ```bash
   mise run run:tracer
   ```

4. **Run the Profiler (requires sudo):**
   Run from the `otel-simulation/` root:
   ```bash
   mise run run:profiler
   ```
   *Note: This task automatically detects the PID of the running `api-server` inside the VM. You can still pass a specific PID manually if needed (e.g. `mise run run:profiler <pid>`).*

---

### Option B: Using Standard Go Commands Manually

1. **Compile & Build the Target API Server:**
   ```bash
   cd api-server
   go build -o bin/api-server
   ```

2. **Compile & Build the Tracer:**
   ```bash
   cd otel-tracer
   go generate
   go build -o bin/otel-tracer
   ```

3. **Compile & Build the Profiler:**
   ```bash
   cd otel-profiler
   go generate
   go build -o bin/otel-profiler
   ```

4. **Run target and tools inside the Linux VM:**
   ```bash
   # Terminal 1: Run server
   ./api-server/bin/api-server
   
   # Terminal 2: Run tracer (requires root)
   sudo ./otel-tracer/bin/otel-tracer ./api-server/bin/api-server
   
   # Terminal 3: Run profiler (requires root and PID)
   sudo ./otel-profiler/bin/otel-profiler <api-server-pid>
   ```

---

## How to Test

Use the provided [api.http](file:///Users/mago/dev/ebpf/otel-simulation/api-server/api.http) file or standard `curl`:

```bash
# Healthcheck
curl http://localhost:8080/health

# Simulated work
curl http://localhost:8080/api/work
```

When you trigger requests, you will see CPU and Memory rate changes in the `otel-profiler` console output:

```text
----------------- SIMULATED OpenTelemetry Profile -----------------
Target PID:          5307
Timestamp:           2026-08-29T22:19:33-03:00

[CPU Metrics]
  CPU Utilization:   8.33%
  CPU Samples/sec:   33 ticks

[Memory Heap Allocation Metrics (mallocgc)]
  Allocated Rate:    0.08 MB/sec
  Allocation Rate:   527 allocs/sec
  Total Heap Alloc:  0.08 MB (cumulative)
  Total Heap Count:  527 allocations (cumulative)
-------------------------------------------------------------------
```
