# eBPF Study and Simulation Repository (Go + Kernel C)

This repository contains a collection of practical, hands-on learning labs and simulations powered by **eBPF (Extended Berkeley Packet Filter)** in the Linux kernel space, managed by userspace control daemons written in **Go (Golang)**.

The environment is fully portable and runs inside a lightweight, pre-configured Linux virtual machine managed by **Lima VM**.

---

## 📁 Repository Structure

The workspace is organized into the following sub-projects:

### 1. [Slides](https://docs.google.com/presentation/d/e/2PACX-1vQ4HW4jYKiE-3sNhtLr16APXL-RibyGE1am2WrjnoEukTs9kK3d91IQ4qq5L7U0UhHzyIa7SsoAXs2d/pub?start=false&loop=false&delayms=3000) (Theoretical Introduction)
A conceptual introduction to the eBPF ecosystem (its architecture, hooks like uprobes, kprobes, tracepoints, socket filters, XDP, and the inner workings of the kernel verifier).

### 2. [``packet-counter/``](file:///Users/mago/dev/ebpf/packet-counter) (XDP Packet Counter)
An introductory, high-performance network packet counter hooked at the **XDP (eXpress Data Path)** level on the network interface. It atomically increments counter maps in kernel memory for every incoming frame before passing the packet up to the traditional OS network stack.

### 3. [``otel/``](file:///Users/mago/dev/ebpf/otel) (OpenTelemetry Observability & Profiling)
* **`otel-tracer/`**: A fully transparent distributed HTTP tracer. Hooks into Go runtime handlers using **Uprobes** to capture and correlate requests, publishing OpenTelemetry trace spans without modifications to the application code.
* **`otel-profiler/`**: CPU profiling (via `perf_event` clock interrupts) and memory heap allocation tracking (via `runtime.mallocgc` uprobes). Includes a native Symbol Resolver in Go to parse binary offsets and map raw instruction pointers to readable function names.

### 4. [``firewall/``](file:///Users/mago/dev/ebpf/firewall) (Cgroup-based Network Policies)
A cgroup-based firewall hooked at `cgroup/connect4` (Cgroups v2). It intercepts outgoing TCP connection requests (`connect()` system calls) and blocks unauthorized traffic dynamically for processes registered in an eBPF blocklist map, responding immediately with `EPERM` (Operation not permitted).

### 5. [``service-mesh/``](file:///Users/mago/dev/ebpf/service-mesh) (Unified eBPF Service Mesh)
A consolidated simulator showcasing a **kernel-native Service Mesh**:
* **Security**: Firewall policies matching socket requests in the kernel.
* **Traffic Control (Canary)**: Dynamic, zero-proxy canary routing (50/50 split) by rewriting port targets inside the `connect()` system call context.
* **Observability**: Live tracing spans, CPU %, and heap memory allocation rates collected per service.
* **Control Panel**: A real-time, terminal-based dashboard displaying active service PIDs, metrics, routing rules, and tracing logs.

---

## 🛠️ Environment Setup (macOS)

Since eBPF is a Linux-native kernel technology, we use **Lima VM** to run a lightweight, virtualized Linux environment on macOS. We have automated this setup in a root-level **Mise** task.

### 1. Provision and Start the VM
From the root of this repository on your macOS host, run:
```bash
mise run setup:lima
```
*This task checks if Homebrew and Lima are installed (installing them if missing) and starts the Linux VM using the provided [lima.yaml](file:///Users/mago/dev/ebpf/lima.yaml) configuration file in non-interactive mode.*

### 2. Access the VM Shell
Once the VM is running, open the Linux shell:
```bash
limactl shell lima
```

### 3. Build and Run Projects
Inside the VM shell, navigate to the mounted folder of any project (e.g., `service-mesh`) and run its local Mise task:
```bash
# Inside the VM shell:
cd ~/dev/ebpf/service-mesh
mise run build
```
*(Note: Tasks loading eBPF bytecode or hooking kernel layers require elevated permissions. The local `mise.toml` scripts automatically apply `sudo` where necessary).*

### 4. Supervised Execution with Prefixed Logs (Docker-Compose Style)
If you want to compile, build, and run all services for a project inside a single terminal session with colored, interleaved log streams (similar to `docker-compose up`), run the following commands directly from the root of this repository on your macOS host:

```bash
# Run Packet Counter
mise run run:packet-counter

# Run OpenTelemetry Auto-Instrumentation (api-server + tracer + profiler)
mise run run:otel

# Run Cgroup Blocker Firewall (3 services + firewall daemon)
mise run run:firewall

# Run Unified Service Mesh (4 services + control panel with log stream)
mise run run:service-mesh
```
*Note: Press `Ctrl+C` in your terminal to gracefully terminate all running services. The host-level supervisor will intercept the signal and cleanly stop all background processes inside the VM, preventing any port leaks.*
