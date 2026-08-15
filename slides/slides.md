---
theme: default
background: '#ffffff'
title: Introduction to eBPF with Go
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

# Introduction to eBPF with Go

<div class="text-xl text-slate-500 mt-4">
  Unlock Linux Kernel Power Safely from Go Userspace
</div>

<div class="abs-br m-6 text-sm" style="color:#94a3b8">
  2026
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
