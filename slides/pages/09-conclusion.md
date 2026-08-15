# Conclusion & Key Takeaways

<div class="grid grid-cols-2 gap-8 mt-8 text-left text-sm">
<div class="hl hl-blue">
<p class="font-bold mb-2">Why eBPF is Game-Changing</p>
<ul class="list-disc ml-4 space-y-1">
  <li><strong>Safe Extensibility</strong>: Runs custom code in kernel space with zero kernel crash risk.</li>
  <li><strong>Superb Performance</strong>: Native execution speed thanks to verification and JIT.</li>
  <li><strong>Zero Instrumentation</strong>: Monitor and secure applications transparently.</li>
</ul>
</div>

<div class="hl hl-green">
<p class="font-bold mb-2">Why Go is the Perfect Partner</p>
<ul class="list-disc ml-4 space-y-1">
  <li><strong>CNCF Compatibility</strong>: Seamless integration with Kubernetes and Docker tools.</li>
  <li><strong>bpf2go simplicity</strong>: Compiles C and embeds bytecode directly into type-safe Go bindings.</li>
  <li><strong>No CGO compiler dependency</strong> during program execution, simplifying deployment.</li>
</ul>
</div>
</div>

<!--
To conclude, eBPF is fundamentally changing how we build infrastructure.
It gives us the ability to extend the kernel safely, run at native speed, and observe or protect applications without modifying them.
And Go is the perfect control plane partner. It allows us to compile, embed, load, and manage eBPF programs easily using pure Go libraries and type-safe tools like bpf2go, and easily deploy them to our Kubernetes clusters.
-->

---
layout: center
---

# Q&A & Resources

<div class="grid grid-cols-2 gap-10 mt-8 text-left text-base">
<div>
<p class="font-bold mb-2">Further Reading</p>
<ul class="list-disc ml-4 space-y-1">
  <li><strong>ebpf.io</strong> — The official eBPF community homepage.</li>
  <li><strong>github.com/cilium/ebpf</strong> — The Cilium Go library.</li>
  <li><strong>ebpf.io/slack</strong> — Join the community Slack channel.</li>
  <li><strong>Cilium / Tetragon repositories</strong> — Great source of production-grade Go+eBPF code.</li>
</ul>
</div>
<div class="card card-purple flex flex-col justify-center items-center">

🐹 **Thank you!**

<p class="text-sm text-slate-600 mt-2 text-center">Questions? Now is the time!</p>

</div>
</div>

<!--
Thank you for your time!
I hope this gives you a great starting point for your own eBPF journey in Go.
I've listed some useful resources on the slide: ebpf.io is the main homepage, the Cilium Go repository is where the code lives, and the Slack community is very friendly and active.
I will now open the floor to any questions you may have.
-->
