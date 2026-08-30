# eBPF XDP Packet Counter

This project implements a simple packet counter using eBPF and XDP (eXpress Data Path). It attaches to the primary network interface inside the Linux kernel and counts incoming network packets atomically.

## Architecture

- **eBPF Program (`counter.c`)**: Defines an array map `pkt_count` and hooks the `xdp` entrypoint. On every incoming packet, it increments the count atomically and passes the packet along to the networking stack (`XDP_PASS`).
- **Go Daemon (`main.go`)**: Loads the eBPF bytecode into the kernel, auto-detects the active non-loopback network interface (or eth0/lo), attaches the XDP program to it, and polls the kernel map every second to print the packet count.

---

## How to Compile & Run

All commands can be run directly from the `packet-counter/` directory using **Mise**:

### 1. Build the project
```bash
mise run build
```

### 2. Run the packet counter (requires root privileges inside VM)
```bash
mise run run
```
