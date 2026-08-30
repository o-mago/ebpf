---
layout: section
---

# Part 7: Real-world eBPF + Go Applications
## Industry-Leading Tools Built on the Same Stack

<!--
Now that we have built a simple packet counter, let's explore how the industry uses this exact same technology stack (eBPF + Go) to solve massive scale networking and observability challenges.
We will look at two key use cases: Cilium for networking and OpenTelemetry for eBPF-based auto-instrumentation.
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

# Observability: OpenTelemetry Auto-Instrumentation

eBPF enables collecting deep performance metrics and traces automatically, without modifying application code, importing SDKs, or redeploying.

<div class="grid grid-cols-2 gap-8 mt-4 text-sm">
<div>
<p class="font-bold text-slate-800">1. Go-specific Auto-Instrumentation</p>
<ul class="list-disc ml-4 space-y-1 mt-1 mb-4 text-slate-700">
  <li>Hooks into compiled Go binaries using <code>uprobes</code> at runtime.</li>
  <li>Correlates network sockets with active Go routines to trace HTTP/gRPC requests and database queries automatically.</li>
  <li>GitHub: <a href="https://github.com/open-telemetry/opentelemetry-go-instrumentation" target="_blank">opentelemetry-go-instrumentation</a></li>
</ul>

<p class="font-bold text-slate-800 mt-4">2. Generic eBPF Instrumentation</p>
<ul class="list-disc ml-4 space-y-1 mt-1 text-slate-700">
  <li>System-wide observability across multiple languages and runtimes.</li>
  <li>Leverages eBPF to intercept socket writes and read HTTP headers directly from network buffers.</li>
  <li>GitHub: <a href="https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation" target="_blank">opentelemetry-ebpf-instrumentation</a></li>
</ul>
</div>
<div>

<div class="card card-purple">
<p class="font-bold text-slate-800 text-xs">Zero Code Changes</p>
<span class="text-xs text-slate-700">DevOps and SRE teams can gain complete visibility into legacy or third-party applications without rebuilds or configuration changes.</span>
</div>

<div class="hl hl-slate mt-4">
<strong>How it works: uprobes & kprobes</strong><br>
Instruments userspace function entry points (e.g. <code>uprobes</code> on HTTP handlers) and kernel events to measure execution latencies.
</div>

</div>
</div>

<!--
The second major use case is observability with OpenTelemetry auto-instrumentation.
Traditionally, telemetry required importing SDKs, editing code, and redeploying.
With eBPF, we can auto-instrument applications at runtime.
First, we have opentelemetry-go-instrumentation, which uses uprobes to hook directly into compiled Go binaries, tracing HTTP/gRPC requests.
Second, opentelemetry-ebpf-instrumentation provides language-agnostic kernel-level auto-instrumentation.
By intercepting kernel socket buffers and events, we capture metrics, network traces, and latencies without a single line of user code change.
-->
