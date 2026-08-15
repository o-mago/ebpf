---
layout: section
---

# Part 4: The Kernel-Space Code (C)
## Analyzing our eBPF Packet Counter Program (`counter.c`)

<!--
Now we will walk through the actual code we have in our repository.
We will look at `counter.c` which runs inside the kernel. It is written in C, and its job is to run at the XDP level (the lowest level of the networking stack) and count every incoming network packet.
-->

---

# Kernel Code Overview: `counter.c`

Here is the complete source code for our kernel-space eBPF program:

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY); 
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} pkt_count SEC(".maps"); 

SEC("xdp") 
int count_packets() {
    __u32 key    = 0; 
    __u64 *count = bpf_map_lookup_elem(&pkt_count, &key); 
    if (count) { 
        __sync_fetch_and_add(count, 1); 
    }
    return XDP_PASS; 
}

char __license[] SEC("license") = "Dual MIT/GPL";
```

<!--
This is the complete program. It is only 25 lines of code!
Let's break down the three main parts of this file:
1. Headers and Map Definition (lines 1-11)
2. The Program Function (lines 13-23)
3. The License Section (line 25)
-->

---

# Defining the Map in C

Let's look at the BPF map definition:

```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY); 
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} pkt_count SEC(".maps"); 
```

<div class="grid grid-cols-2 gap-8 mt-4 text-xs">
<div class="hl hl-slate">

**Fields explained:**
* `type`: We use an **ARRAY** map. Hash maps are better for arbitrary keys (like IPs), but arrays are faster for fixed indexes.
* `key`: `__u32` (32-bit unsigned integer). Since the size is 1, our only key will be index `0`.
* `value`: `__u64` (64-bit unsigned integer) representing the packet count.

</div>
<div class="hl hl-blue">

**The `SEC` macro:**
* `SEC(".maps")` tells the Clang compiler to place this struct in a special ELF section named `.maps`.
* The kernel reads this section to allocate the actual map in kernel memory when the program is loaded.

</div>
</div>

<!--
To count packets, we need memory. We declare a BPF map named `pkt_count`.
We use BTF-style map declarations (eBPF Type Format).
The map type is `BPF_MAP_TYPE_ARRAY`. Since it's an array, it's indexed by 32-bit integers (`__u32`), and our value is a 64-bit counter (`__u64`). We only need to store one number, so `max_entries` is set to 1.
The `SEC(".maps")` macro is crucial. It tells the compiler to put this struct in a specific section of the ELF binary, which the loader (Go) and the kernel use to locate and instantiate the map.
-->

---

# The XDP Program Hook

The program logic is contained in the `count_packets` function:

```c
SEC("xdp") 
int count_packets() {
    __u32 key    = 0; 
    __u64 *count = bpf_map_lookup_elem(&pkt_count, &key); 
    if (count) { 
        __sync_fetch_and_add(count, 1); 
    }
    return XDP_PASS; 
}
```

<div class="grid grid-cols-2 gap-8 mt-2 text-xs">
<div>

* `SEC("xdp")`: Defines the hook type. This function runs inside the network driver, processing packets *before* they reach the kernel's main IP stack.
* `bpf_map_lookup_elem`: Built-in eBPF helper function to search our map for key `0`.
* `if (count)`: **Crucial Verifier Check!** You must check if the returned pointer is not NULL before dereferencing it.

</div>
<div>

* `__sync_fetch_and_add`: Atomic compiler built-in. Multiple CPU cores can process network packets in parallel; atomic addition prevents race conditions.
* `XDP_PASS`: Tells the kernel to let the packet continue up the normal network stack. Other options include `XDP_DROP` (firewall) or `XDP_TX` (bounce packet back out the same interface).

</div>
</div>

<!--
Now let's look at the function.
`SEC("xdp")` tells the kernel this is an XDP (eXpress Data Path) program. It attaches directly to the network interface card (NIC) driver.
First, we look up key `0` in our map.
Next, we check if `count` is not null. Without this check, the verifier will reject the code.
If valid, we increment the count. We use `__sync_fetch_and_add` which is atomic, because multiple CPU cores might run this function simultaneously for different packets.
Finally, we return `XDP_PASS` which lets the packet proceed to the normal network stack. If we wanted to drop the packet, we would return `XDP_DROP`.
-->
