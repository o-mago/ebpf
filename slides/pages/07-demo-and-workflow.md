---
layout: section
---

# Part 6: Compiling & Running eBPF
## Hands-on Lifecycle of an eBPF+Go Application

<!--
Now we will go through how to compile and run this application.
eBPF development requires compiling C code to BPF bytecode, combining it with Go, and executing it with specific Linux privileges.
Let's look at the complete build and run workflow.
-->

---

# The Compilation Pipeline

We rely on the standard Go toolchain integrated with `bpf2go`.

<div class="grid grid-cols-2 gap-8 mt-4 text-sm">
<div>

**Step 1: Code Generation**
Compile C to BPF ELF and generate Go wrappers.
```bash
go generate ./...
```
*Behind the scenes*: `bpf2go` checks if Clang is installed, reads the `//go:generate` directive, compiles `counter.c` to BPF bytecode, and writes the Go wrapper source files.

</div>
<div>

**Step 2: Build Binary**
Build the combined binary.
```bash
go build -o ebpf-test
```
*Behind the scenes*: The standard Go compiler compiles `main.go` along with the generated `counter_bpfel.go` files, compiling the embedded BPF ELF bytecode directly into the executable binary.

</div>
</div>

<div class="hl hl-blue mt-6">
<strong>Generated Files in the Workspace</strong><br>
Running <code>go generate</code> creates <code>counter_bpfel.o</code> (compiled BPF bytecode) and <code>counter_bpfel.go</code> (Go struct API).
</div>

<!--
To compile the application, we start by running `go generate ./...`.
This runs `bpf2go`, which compiles the C code into BPF bytecode (creating the `.o` object files) and generates the corresponding Go files (`counter_bpfel.go`).
Once code generation is complete, we run the standard `go build -o ebpf-test`. The Go compiler builds the userspace code and embeds the BPF bytecode inside the binary, producing a single, self-contained executable.
-->

---

# Running with Linux Capabilities

eBPF programs interact directly with kernel memory and network drivers. Therefore, execution requires special Linux privileges.

<div class="grid grid-cols-2 gap-8 mt-4 text-sm">
<div>

**Option 1: Using `sudo` (Simple)**
Run the compiled binary with full administrative privileges:
```bash
sudo ./ebpf-test
```

**Option 2: Granting Specific Capabilities (Best Practice)**
Instead of granting full root access (`sudo`), grant only the capabilities needed to load eBPF programs:
```bash
# Set capabilities on the binary
sudo setcap cap_bpf,cap_net_admin,cap_sys_admin+ep ./ebpf-test

# Run as a normal user
./ebpf-test
```

</div>
<div>

<p class="font-bold text-slate-800">Key Capabilities Required</p>
<ul class="list-disc ml-4 space-y-2 mt-1">
  <li><strong>CAP_BPF</strong>: Introduced in kernel 5.8. Allows loading eBPF programs and creating maps.</li>
  <li><strong>CAP_NET_ADMIN</strong>: Required to attach/detach XDP programs to network interfaces.</li>
  <li><strong>CAP_SYS_ADMIN</strong>: Required for helper function operations and compatibility on older kernels.</li>
</ul>

</div>
</div>

<!--
Since eBPF runs inside kernel memory and hooks into system devices, you cannot load it as a standard user.
You need special capabilities.
For development, you can simply run it with `sudo ./ebpf-test`.
In production, running everything as root is a security risk. Best practice is to use `setcap` to assign specific capabilities to your binary.
We assign `cap_bpf` to load programs/maps, `cap_net_admin` to attach our XDP code to the network card, and `cap_sys_admin` for compatibility. This lets the binary load eBPF without full root access.
-->

---

# Testing the Application

Once the application is running, it will print `Counting incoming packets on eth0...` and log the packet count every second.

<div class="grid grid-cols-2 gap-8 mt-4 text-sm">
<div>

**Checking Active eBPF Programs**
You can use the official kernel tool `bpftool` to verify that our program is loaded:
```bash
# List all active eBPF programs
sudo bpftool prog list

# List all active maps
sudo bpftool map list
```

**Generating Network Traffic**
To see the counter increase, generate traffic through the interface in another terminal:
```bash
# Ping a local IP or gateway
ping -c 10 1.1.1.1

# Generate HTTP requests
curl https://google.com
```

</div>
<div>

<div class="card card-green">
<p class="font-bold text-slate-800">Sample Console Output</p>
<pre class="bg-slate-900 text-slate-100 p-3 rounded mt-2 text-xs font-mono">
$ sudo ./ebpf-test
Counting incoming packets on eth0..
Received 0 packets
Received 12 packets
Received 34 packets
Received 78 packets
^CReceived signal, exiting..
</pre>
</div>

</div>
</div>

<!--
Once the program starts, it attaches to the interface. You can test it by generating some network traffic.
In a separate terminal, run `ping` or `curl`. You should see the logged packet count rise immediately.
You can also inspect the kernel state using `bpftool prog list` or `bpftool map list`. You'll see our `count_packets` program and `pkt_count` map loaded in kernel space, showing that our Go agent is communicating with the kernel.
-->
