# eBPF Packet Counter with Go

This repository contains a practical, introductory example of how to build a userspace agent in **Go (Golang)** that connects to and manages an **eBPF (Extended Berkeley Packet Filter)** program running inside the Linux kernel space.

---

## 📋 What does the code do?

The project is a high-performance **network packet counter** that intercepts traffic at the lowest possible level of the Linux networking stack (XDP). It consists of two main parts:

### 1. Kernel-Space: `app/counter.c` (C)
* An eBPF program attached to the **XDP (eXpress Data Path)** hook.
* It intercepts every incoming packet on the configured network interface.
* It atomically increments (`__sync_fetch_and_add`) a counter inside a `BPF_MAP_TYPE_ARRAY` **BPF Map** allocated in kernel memory.
* It returns `XDP_PASS`, allowing the packet to proceed normally up the network stack.

### 2. User-Space: `app/main.go` (Go)
* Uses the `github.com/cilium/ebpf` library to load the compiled eBPF bytecode into the Linux kernel.
* Dynamically resolves a suitable, active network interface on the system (looking for `eth0`, any active interface, or falling back to the loopback `lo` interface).
* Attaches the eBPF program to the resolved network interface via `link.AttachXDP`.
* Periodically polls the counter from the BPF Map every second (`objs.PktCount.Lookup`) and logs the count to the console.

---

## 🚀 How to Run the Project

Since eBPF is a **Linux** kernel technology, you need a Linux environment to compile and run the actual eBPF code. On macOS, the program compiles a fallback stub indicating that execution requires Linux.

### Prerequisites
* **Linux Kernel 5.8+** (5.11+ is recommended to avoid adjusting `rlimit` lockable memory limits).
* **Go 1.24+** installed.
* **Clang** and **LLVM** installed (used by `bpf2go` to compile the C code).
* **llvm-strip** (usually bundled with LLVM).

---

### Option 1: Compiling and Running Locally (Linux)

1. **Generate the Go wrappers and BPF bytecode**:
   Inside the `app/` directory, run `go generate` to trigger the `bpf2go` tool (configured in [gen.go](file:///Users/mago/dev/ebpf/app/gen.go)):
   ```bash
   cd app
   go generate
   ```
   *This generates the `counter_bpfel.go`, `counter_bpfel.o`, `counter_bpfeb.go`, and `counter_bpfeb.o` files.*

2. **Compile the Go application**:
   ```bash
   go build -o ebpf-test
   ```

3. **Run the program**:
   eBPF requires elevated privileges to load code into the kernel and attach to network interfaces.

   * **Simple Method (using sudo)**:
     ```bash
     sudo ./ebpf-test
     ```
   
   * **Recommended Method (using Capabilities only)**:
     Avoid running the entire process as root by granting specific capabilities to the compiled binary:
     ```bash
     sudo setcap cap_bpf,cap_net_admin,cap_sys_admin+ep ./ebpf-test
     ./ebpf-test
     ```

4. **Generate traffic to test**:
   In another terminal, send pings or HTTP requests to see the packet counter rise:
   ```bash
   ping -c 10 1.1.1.1
   # or
   curl https://google.com
   ```

---

### Option 2: Running via Docker (Linux)

If you are running on a Linux host, you can compile and execute the application encapsulated in a privileged Docker container:

1. **Spin up the services**:
   In the root of the project (where `docker-compose.yaml` is located), execute:
   ```bash
   docker compose up --build
   ```
   *The container compiles the C code, builds the Go binary, and runs the application in `privileged: true` mode to allow interaction with the network interfaces.*

---

### Developing on macOS

If you are on a Mac, the project builds out of the box using `go build` but runs the friendly stub implemented in [main_stub.go](file:///Users/mago/dev/ebpf/app/main_stub.go).

To run the actual eBPF code from a Mac:
1. Install **Lima**:
   ```bash
   brew install lima
   ```
2. Spin up the pre-configured Linux (Ubuntu 26.04) VM using the provided [lima.yaml](file:///Users/mago/dev/ebpf/lima.yaml):
   ```bash
   limactl start lima.yaml
   ```
3. Enter the VM shell:
   ```bash
   limactl shell lima
   ```
4. Inside the VM, navigate to the project directory (your home directory is automatically mounted):
   ```bash
   cd ~/dev/ebpf/app
   ```
   *(Note: All dependencies like Clang, LLVM, kernel headers, and Go 1.27.0 are already pre-installed by the provisioning script).*
5. Proceed with **Option 1** inside the VM shell.