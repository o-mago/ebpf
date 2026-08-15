---
layout: section
---

# Part 7: Real-world eBPF + Go Applications
## Industry-Leading Tools Built on the Same Stack

<!--
Now that we have built a simple packet counter, let's explore how the industry uses this exact same technology stack (eBPF + Go) to solve massive scale networking, observability, and security challenges.
We will look at three flagship open-source projects: Cilium, Pixie, and Tetragon.
-->

---

# Networking: Cilium

Cilium is the industry-standard container network interface (CNI) for Kubernetes, replacing legacy Linux networking components like `iptables`.

<div class="grid grid-cols-2 gap-8 mt-4 text-sm">
<div>
<p class="font-bold mb-1">The Problem with IPTables</p>
<ul class="list-disc ml-4 space-y-1 mb-4 text-slate-700">
  <li>Kubernetes networks route traffic using IP rules.</li>
  <li><code>iptables</code> matches traffic using sequential lists. As clusters grow to thousands of services, evaluating these lists sequentially on every packet degrades networking performance.</li>
</ul>

<p class="font-bold mb-1">The Cilium eBPF Solution</p>
<ul class="list-disc ml-4 space-y-1 text-slate-700">
  <li>Replaces <code>iptables</code> routing lists with highly efficient hash maps indexed in kernel space.</li>
  <li>Can bypass the TCP/IP stack entirely for container-to-container communication on the same host, routing packets instantly.</li>
</ul>
</div>
<div>

<div class="hl hl-blue">
<strong>Unmatched Scale</strong><br>
Cilium handles millions of routing decisions per second with flat latency, regardless of the size of the cluster.
</div>

<div class="hl hl-slate mt-4">
<strong>Service Mesh Without Sidecars</strong><br>
Cilium uses eBPF to route and monitor HTTP/gRPC traffic, eliminating the need for heavy sidecar proxies (like Envoy in Istio) for basic transit.
</div>

</div>
</div>

<!--
The first major use case is networking.
Cilium is a CNCF graduated project used by Google, AWS, and Microsoft for managed Kubernetes networking.
Traditionally, Linux networks rely on iptables. The problem is that iptables is linear—every packet must check rules one-by-one. In a large Kubernetes cluster with thousands of pods, this causes massive CPU usage and packet delays.
Cilium replaces iptables with eBPF maps. Instead of a linear list, it does a O(1) map lookup.
It can also bypass the kernel's heavy TCP/IP stack for local pods, redirecting packets directly from one container's socket to another, achieving near-wire speed.
-->

---

# Observability: Pixie & Hubble

eBPF enables collecting deep performance metrics and application logs without modifying a single line of application code or deploying sidecars.

<div class="grid grid-cols-2 gap-8 mt-4 text-sm">
<div>
<p class="font-bold text-slate-800">1. Zero-Instrumentation Profiling</p>
<ul class="list-disc ml-4 space-y-1 mt-1 mb-4 text-slate-700">
  <li>eBPF can inspect stack traces of running binaries (Go, Python, C++, Java) by hooking into kernel schedulers.</li>
  <li>Allows constructing continuous profiling flame graphs in production with &lt;1% CPU overhead.</li>
</ul>

<p class="font-bold text-slate-800 mt-4">2. Protocol Parsing in Kernel</p>
<ul class="list-disc ml-4 space-y-1 mt-1 text-slate-700">
  <li>Hubble parses common protocols (HTTP, gRPC, PostgreSQL, Redis) by reading network socket buffers directly.</li>
  <li>Instantly provides latency metrics, error rates, and request payloads without changing application code.</li>
</ul>
</div>
<div>

<div class="card card-purple">
<p class="font-bold text-slate-800">How it works: kprobes & uprobes</p>
<ul class="list-disc ml-4 space-y-1 mt-1 text-xs text-slate-700">
  <li><strong>kprobes</strong>: Attach to any kernel function to monitor system behavior.</li>
  <li><strong>uprobes</strong>: Attach to userspace function entry points (e.g., tracking a Go function execution).</li>
  <li><strong>uretprobes</strong>: Monitor userspace function returns to calculate exact latency.</li>
</ul>
</div>

</div>
</div>

<!--
The second use case is observability, spearheaded by projects like Hubble and Pixie.
Traditionally, to get APM trace data, you had to import library SDKs, write code, re-compile, and redeploy.
With eBPF, we can trace function calls without touching the application code.
We use uprobes to attach to functions in userspace binaries. When a function executes, the eBPF program reads its registers and arguments.
By tracing the entry and return of functions, we can calculate the exact latency of API calls, database queries, and internal functions in real-time, for all applications on the machine, automatically.
-->

---

# Security Enforcement: Tetragon

Tetragon is a real-time security auditing and runtime enforcement agent built on eBPF and Go.

<div class="grid grid-cols-2 gap-8 mt-4 text-sm">
<div>
<p class="font-bold mb-1">Traditional Auditing vs. Tetragon</p>
<ul class="list-disc ml-4 space-y-1 mb-4 text-slate-700">
  <li><strong>Traditional</strong>: Parse logs asynchronously after an event occurs (e.g., systemd journal, auditd). If an attacker deletes the logs or escapes the namespace, the trace is lost.</li>
  <li><strong>Tetragon</strong>: Monitors syscalls synchronously in kernel space. Traces file execution, socket connections, namespace changes, and privilege escalations instantly.</li>
</ul>

<p class="font-bold mb-1">Active Kernel-Level Enforcement</p>
<ul class="list-disc ml-4 space-y-1 text-slate-700">
  <li>Tetragon can intercept a syscall and inject an error code (e.g., override system call to return <code>EACCES</code>).</li>
  <li>It can send a <code>SIGKILL</code> directly from the kernel to terminate a compromised process before the write operation actually commits to disk.</li>
</ul>
</div>
<div>

<div class="hl hl-orange">
<strong>Container-Aware Auditing</strong><br>
Because eBPF can inspect cgroup metadata, Tetragon maps low-level system actions to Kubernetes namespaces and pods automatically, providing human-readable cloud security logs.
</div>

</div>
</div>

<!--
The third use case is security, represented by Tetragon.
Traditional security tools run in userspace and parse logs after the fact. If an attacker gains root access, they can disable auditing tools or delete logs.
Tetragon hooks directly into system calls at the kernel level.
It can detect namespace escapes, privilege escalations, or unauthorized file access.
More importantly, it can do active enforcement. It doesn't just log that a file was read; it can block the syscall or send a SIGKILL directly from the kernel, terminating the malicious process before it can do harm.
And since eBPF understands namespaces and cgroups, Tetragon automatically tags these events with the Kubernetes pod name, namespace, and container ID.
-->
