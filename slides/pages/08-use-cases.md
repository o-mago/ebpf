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

Cilium is the industry-standard CNI for Kubernetes, replacing legacy components like `iptables` with high-performance eBPF routing.

<div class="grid gap-8 mt-4" style="grid-template-columns: 2.2fr 1fr">
<div class="grid grid-cols-2 gap-6 text-xs">
<div>
<p class="font-bold mb-1 text-slate-800 text-sm">The IPTables Bottleneck</p>
<ul class="list-disc ml-4 space-y-1 text-slate-600">
  <li>Sequential rule checking scales poorly.</li>
  <li>Evaluating rules on every packet degrades latency at scale.</li>
</ul>

<p class="font-bold mb-1 mt-3 text-slate-800 text-sm">The Cilium Solution</p>
<ul class="list-disc ml-4 space-y-1 text-slate-600">
  <li>Uses fast O(1) hash map lookups in kernel.</li>
  <li>Bypasses TCP/IP stack for local containers.</li>
</ul>
</div>
<div>
<div class="hl hl-blue p-2">
<strong>Flat Latency</strong><br />
Handles millions of routing decisions per second at any scale.
</div>

<div class="hl hl-slate p-2 mt-3">
<strong>Sidecarless Mesh</strong><br />
Bypasses Envoy proxies for basic transit, routing HTTP/gRPC via eBPF.
</div>
</div>
</div>
<div class="flex flex-col items-center justify-center">
  <img src="https://cdn.jsdelivr.net/gh/cilium/cilium@main/Documentation/images/logo-solo.svg" alt="Cilium Logo" class="w-24 h-auto object-contain" />
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

eBPF enables collecting performance metrics and traces automatically without code changes, SDK imports, or redeployments.

<div class="grid gap-8 mt-4" style="grid-template-columns: 2.2fr 1fr">
<div class="grid grid-cols-2 gap-6 text-xs">
<div>
<p class="font-bold text-slate-800 text-sm">1. Go Auto-Instrumentation</p>
<ul class="list-disc ml-4 space-y-1 text-slate-600">
  <li>Hooks into Go binaries using <code>uprobes</code> at runtime.</li>
  <li>Correlates sockets with goroutines for HTTP/gRPC and DB tracing.</li>
  <li><strong>Sidecar Model</strong>: Runs as a sidecar container in the Pod, isolating security context.</li>
  <li><strong>Easy Hybrid Spans</strong>: Intercepts no-op SDK calls; no manual Collector or Provider setup needed in code.</li>
  <li><a href="https://github.com/open-telemetry/opentelemetry-go-instrumentation" target="_blank">Go Instrumentation Repo</a></li>
</ul>
</div>
<div>
<p class="font-bold text-slate-800 text-sm">2. Generic eBPF Instrumentation</p>
<ul class="list-disc ml-4 space-y-1 text-slate-600">
  <li>System-wide, multi-language observability.</li>
  <li>Intercepts socket writes and reads headers directly from network buffers.</li>
  <li><strong>DaemonSet Model</strong>: Runs globally once per node to monitor all pods system-wide.</li>
  <li><strong>Complex Hybrid Spans</strong>: Out-of-process execution requires manual initialization of OTel SDK/exporters in code.</li>
  <li><a href="https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation" target="_blank">eBPF Instrumentation Repo</a></li>
</ul>
</div>
</div>
<div class="flex flex-col items-center justify-center gap-3">
  <img src="https://raw.githubusercontent.com/cncf/artwork/main/projects/opentelemetry/horizontal/color/opentelemetry-horizontal-color.svg" alt="OpenTelemetry Logo" class="w-32 h-auto object-contain" />
  <div class="card card-purple p-2 text-[10px] text-center">
    <strong>Zero Code Changes</strong><br />Gain visibility without rebuilds.
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

---

# Deployment Architecture: DaemonSet vs. Sidecar

<div class="grid grid-cols-2 gap-8 mt-6">
  <div class="flex flex-col items-center">
    <p class="font-bold text-sm text-slate-800 mb-3">DaemonSet Model (Generic eBPF Instrumentation)</p>
    <img src="/otel-daemonset.png" alt="OTel DaemonSet Model" class="h-64 w-auto object-contain rounded-xl border border-slate-200 shadow-sm" />
  </div>
  <div class="flex flex-col items-center">
    <p class="font-bold text-sm text-slate-800 mb-3">Sidecar Model (Go Auto-Instrumentation)</p>
    <img src="/otel-sidecar.png" alt="OTel Sidecar Model" class="h-64 w-auto object-contain rounded-xl border border-slate-200 shadow-sm" />
  </div>
</div>

<!--
To visualize the difference:
On the left, the DaemonSet model. We have one single agent on the host machine. It monitors Pod A and Pod B globally via kernel socket filters and syscall kprobes.
On the right, the Sidecar model. Each application Pod gets a sidecar container. They share the process namespace. The Go application uses the default no-op SDK, and the sidecar agent hijacks the memory pointers, dynamically injecting trace context.
-->
