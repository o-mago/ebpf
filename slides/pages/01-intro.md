# About me

<div class="grid gap-6 mt-1" style="grid-template-columns: 180px 1fr 140px">

<div class="flex flex-col items-center gap-3">
  <img src="/speaker-photo.png" alt="Photo" class="rounded-2xl object-cover" style="width:160px;height:160px;background:#f1f5f9;border:2px solid #e2e8f0" />
  <img src="/cat-photo.jpg" alt="Genevieve" class="rounded-xl object-cover" style="width:160px;height:160px;background:#f1f5f9;border:2px solid #e2e8f0" />
</div>


<div class="flex flex-col justify-between py-1">
  <p class="text-2xl font-bold mb-2" style="color:#0f172a">Alexandre Cabral</p>
  <ul class="text-base text-slate-700 space-y-2">
    <li>📍 Juiz de Fora - MG</li>
    <li>💼 Senior Software Engineer @ Stone</li>
    <li>🐹 Golang Google Developer Expert</li>
    <li>🔥 Botafogo</li>
    <li>🌐 Tech Hub JF Organizer</li>
    <li>🧙‍♂️ Mago</li>

  </ul>
</div>

<div class="flex flex-col items-center gap-2">
  <img src="/qrcode.png" alt="QR Code" style="width:200px;height:200px;min-width:200px;min-height:200px;background:#f1f5f9;border:2px solid #e2e8f0;border-radius:8px;object-fit:fill" />
  <p class="text-xs text-center" style="color:#94a3b8">My social links</p>
</div>

</div>

<!--
Personal presentation slide. Place the files in slides/public/:
- speaker-photo.png — your photo
- cat-photo.jpg — photo of Genevieve
- qrcode.png — QR code of social networks
-->

---
layout: center
---

# Agenda

<div class="grid grid-cols-2 gap-10 mt-8 text-left text-base">
<div class="hl hl-slate">
<p class="font-bold mb-2">Theory</p>
<ol class="list-decimal ml-4 space-y-1">
  <li><strong>What is eBPF?</strong> (Kernel vs User Space, Sandboxing)</li>
  <li><strong>eBPF Architecture</strong> (Verifier, JIT, Maps)</li>
  <li><strong>The Go + eBPF Synergy</strong> (Cilium <code>ebpf-go</code>, <code>bpf2go</code>)</li>
</ol>
</div>

<div class="hl hl-blue">
<p class="font-bold mb-2">Practice & Use Cases</p>
<ol class="list-decimal ml-4 space-y-1" start="4">
  <li><strong>The eBPF Code (C)</strong> (A closer look at <code>counter.c</code>)</li>
  <li><strong>The Go Control Plane</strong> (Loading, Attaching, Map Querying)</li>
  <li><strong>Real-world Applications</strong> (Networking, Security, Observability)</li>
</ol>
</div>
</div>

<!--
We will divide our time into two parts.
First, we will lay down the conceptual foundations of eBPF. We'll understand what it is, why it is a paradigm shift, and how the internals work. We will also see why Go is a premier language for building control planes.
Second, we will dive into a real-world code example. We have a packet counter running at the XDP level. We'll look at the C program that runs in the kernel, and the Go loader that runs in userspace. We will conclude with real-world projects like Cilium and Tetragon.
-->

---

# Prerequisites & Setup

<div class="grid grid-cols-2 gap-8 mt-4">
<div>

<div class="card card-blue mb-4">
<p class="font-bold text-slate-800">What we assume you know</p>
<ul class="text-sm text-slate-700 list-disc ml-4 mt-1 space-y-1">
  <li>Basic Go syntax and package management</li>
  <li>Basic C syntax (reading pointers and structs)</li>
  <li>Familiarity with the Linux command line</li>
  <li>Basic TCP/IP networking concepts</li>
</ul>
</div>

<div class="card card-purple">
<p class="font-bold text-slate-800">No Kernel Programming Experience Required!</p>
<p class="text-xs text-slate-600 mt-1">You don't need to be a Linux kernel wizard. eBPF is designed to be accessible to systems and applications engineers alike.</p>
</div>

</div>
<div>

<p class="font-bold mb-2">Development Environment</p>

<div class="space-y-3">
<div class="hl hl-green text-sm">
<strong>Modern Linux Kernel</strong> — Linux 5.11+ is recommended for the best experience (eliminates memlock limits by default).
</div>
<div class="hl hl-orange text-sm">
<strong>Clang / LLVM</strong> — Needed to compile our C code to BPF bytecode.
</div>
<div class="hl hl-slate text-sm">
<strong>Cilium ebpf package</strong> — Pure Go library that reads the compiled ELF, loads objects, and manages maps.
</div>
</div>

</div>
</div>

<!--
Briefly clarify the expectations. Assure the audience that they do not need to be kernel hackers. 
Specify that a modern Linux kernel is required to run the code because eBPF is a Linux-only technology. Explain that while compiling needs Clang, the userspace Go side is fully standard Go code.
-->
