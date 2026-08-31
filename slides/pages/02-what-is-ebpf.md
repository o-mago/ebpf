---
layout: section
---

# Part 1: What is eBPF?
## Understanding the Linux Kernel Paradigm Shift

<!--
Now we begin with our first part: What is eBPF and why is it considered a paradigm shift?
To understand eBPF, we first need to look at how we traditionally extend or modify the behavior of the Linux kernel, and the trade-offs involved.
-->

---

# The Linux Kernel Challenge

How do we add new functionality (e.g., a new security monitor or a custom router) to the Linux Kernel?

<div class="grid grid-cols-2 gap-8 mt-4 text-sm">
<div>

<p class="font-bold text-slate-800">1. Upstream Kernel Development</p>
<ul class="list-disc ml-4 text-slate-600 mt-1 space-y-1">
  <li>Propose changes to the Linux Kernel community.</li>
  <li><strong>Pros</strong>: High code quality, official support.</li>
  <li><strong>Cons</strong>: Can take <strong>years</strong> to get merged, and years more for users to adopt the new kernel version.</li>
</ul>

<div class="hl hl-slate mt-4">
<strong>Verdict</strong>: Too slow for fast-paced feature development and prototyping.
</div>

</div>
<div>

<p class="font-bold text-slate-800">2. Kernel Modules (LKM)</p>
<ul class="list-disc ml-4 text-slate-600 mt-1 space-y-1">
  <li>Write C code that loads dynamically into kernel space.</li>
  <li><strong>Pros</strong>: Fast feedback loop, full access.</li>
  <li><strong>Cons</strong>: A single crash or memory leak in your module takes down the <strong>entire operating system</strong> (panic).</li>
</ul>

<div class="hl hl-orange mt-4">
<strong>Verdict</strong>: Extremely risky for production deployments.
</div>

<img src="https://media.giphy.com/media/zyclIRxMwlY40/giphy.gif" alt="Kernel Modules Fire" class="w-48 h-24 rounded mt-3 object-cover mx-auto" />

</div>
</div>

<!--
Historically, Linux development has had a stark boundary.
If you wanted to add a feature to the kernel, you had two options. 
First: write a patch and submit it to LKML. This is a very slow process. Even if your patch is accepted, it takes years to trickle down to Debian, Red Hat, or Ubuntu LTS releases.
Second: write a Linux Kernel Module (LKM). This compiles into kernel space, but if you make a mistake, you crash the entire machine (Kernel Panic). For critical infrastructure, this is often unacceptable.
-->

---

# eBPF: A Revolutionary Solution

eBPF (Extended Berkeley Packet Filter) allows running sandboxed programs inside the Linux kernel without modifying kernel source code or loading kernel modules.

<div class="grid grid-cols-2 gap-8 mt-6">
<div>
<p class="font-bold mb-2">The "Web Browser" Analogy</p>
<ul class="list-disc ml-4 space-y-2 text-sm text-slate-700">
  <li><strong>The Past</strong>: Webpages were static. To add interactive features, you had to update the browser source code or use dangerous plugins (ActiveX, Flash).</li>
  <li><strong>JavaScript</strong>: Introduced a secure, sandboxed engine in the browser. Anyone could write custom code that runs safely on webpage events.</li>
  <li><strong>eBPF is JavaScript for the Kernel</strong>: It runs code safely on kernel events (syscalls, network packets, tracepoints).</li>
</ul>
</div>
<div>

<div class="space-y-4">
<div class="hl hl-blue">
<strong>Event-Driven</strong>: eBPF programs execute only when a specific hook point (event) in the kernel is triggered.
</div>
<div class="hl hl-green">
<strong>High Performance</strong>: Runs at native speed due to Just-In-Time (JIT) compilation directly to machine instructions.
</div>
<div class="hl hl-orange">
<strong>Safe by Design</strong>: The kernel validates every instruction before loading, guaranteeing it won't crash the system.
</div>
</div>

</div>
</div>

<!--
eBPF solves this by providing a third way. It is a sandboxed virtual machine built directly into the Linux kernel.
Think of it like JavaScript for the kernel. Before JS, you had to build a custom browser extension or wait for browser updates to build interactive web apps. JS changed that by allowing safe, event-driven, sandboxed code to execute in the browser.
Similarly, eBPF allows developers to run safe, sandboxed, event-driven code inside the kernel when specific events trigger—without rebooting or compromising kernel safety.
-->
