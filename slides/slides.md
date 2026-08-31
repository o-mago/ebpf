---
theme: default
background: '#ffffff'
title: Hacking the Kernel with Go
info: |
  An introductory presentation on leveraging the power of eBPF (Extended Berkeley Packet Filter) using Golang.
class: text-center
drawings:
  persist: false
transition: slide-left
mdc: true
colorSchema: light
fonts:
  sans: 'Helvetica Neue, Helvetica, Arial'
  provider: none
---

# Hacking the Kernel with Go

<div class="text-xl text-slate-500 mt-4">
  A Practical Introduction to eBPF
</div>

<div class="flex flex-col items-center">
  <img src="/ebpf-go.png" alt="OTel Sidecar Model" class="h-50 pt-10 w-auto object-contain" />
</div>

<!--
Welcome everyone to "Introduction to eBPF with Go". 
Today, we are going to explore eBPF (Extended Berkeley Packet Filter), why it is one of the most exciting technologies in systems engineering, and how we can use Go to write high-performance userspace agents that interact with eBPF programs running inside the Linux kernel.
We will walk through how eBPF works, why Go is a perfect fit, and look at actual code—both in C for the kernel and Go for the control plane.
-->

---
src: ./pages/01-intro.md
---

---
src: ./pages/02-what-is-ebpf.md
---

---
src: ./pages/03-ebpf-architecture.md
---

---
src: ./pages/04-ebpf-go.md
---

---
src: ./pages/05-ebpf-c-program.md
---

---
src: ./pages/06-go-loader.md
---

---
src: ./pages/07-demo-and-workflow.md
---

---
src: ./pages/08-use-cases.md
---

---
src: ./pages/09-conclusion.md
---
