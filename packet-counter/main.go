//go:build linux

package main

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		slog.Error("Failed to remove memlock", "error", err)
		os.Exit(1)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs counterObjects
	if err := loadCounterObjects(&objs, nil); err != nil {
		slog.Error("Failed to load eBPF objects", "error", err)
		os.Exit(1)
	}
	defer objs.Close()

	iface, err := getInterface()
	if err != nil {
		slog.Error("Failed to find network interface", "error", err)
		os.Exit(1)
	}

	// Attach count_packets to the network interface.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.CountPackets,
		Interface: iface.Index,
	})
	if err != nil {
		slog.Error("Failed to attach XDP program", "error", err)
		os.Exit(1)
	}
	defer l.Close()

	slog.Info("Counting incoming packets", "interface", iface.Name)

	// Periodically fetch the packet counter from PktCount
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	// Start a dummy HTTP server so we can generate traffic from api.http
	go func() {
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			slog.Info("Received HTTP request", "path", r.URL.Path)
			w.Write([]byte("Packet received!\n"))
		})
		slog.Info("Starting dummy HTTP server to receive traffic on :8080")
		if err := http.ListenAndServe(":8080", nil); err != nil {
			slog.Error("HTTP server failed", "error", err)
		}
	}()

	for {
		select {
		case <-ticker.C:
			var count uint64
			err := objs.PktCount.Lookup(uint32(0), &count)
			if err != nil {
				slog.Error("Map lookup failed", "error", err)
				os.Exit(1)
			}
			slog.Info("Packet count update", "packets", count)
		case sig := <-stop:
			slog.Info("Received shutdown signal, exiting...", "signal", sig.String())
			return
		}
	}
}

// getInterface searches for a suitable network interface to attach our XDP program.
func getInterface() (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	// For local testing with api.http, we want to listen on loopback first
	// because port-forwarded traffic from the host arrives via 'lo'.
	if iface, err := net.InterfaceByName("lo"); err == nil {
		return iface, nil
	}

	// Then, try to look for eth0 (common in containers/VMs)
	if iface, err := net.InterfaceByName("eth0"); err == nil {
		return iface, nil
	}

	// Second, try to find any active non-loopback interface
	for _, iface := range ifaces {
		if (iface.Flags&net.FlagLoopback) == 0 && (iface.Flags&net.FlagUp) != 0 {
			return &iface, nil
		}
	}

	// Fallback to loopback interface if nothing else is up
	if iface, err := net.InterfaceByName("lo"); err == nil {
		return iface, nil
	}

	if len(ifaces) > 0 {
		return &ifaces[0], nil
	}

	return nil, fmt.Errorf("no network interfaces found")
}
