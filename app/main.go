//go:build linux

package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs counterObjects
	if err := loadCounterObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	iface, err := getInterface()
	if err != nil {
		log.Fatal("Finding interface:", err)
	}

	// Attach count_packets to the network interface.
	link, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.CountPackets,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	defer link.Close()

	log.Printf("Counting incoming packets on %s..", iface.Name)

	// Periodically fetch the packet counter from PktCount,
	// exit the program when interrupted.
	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	for {
		select {
		case <-tick:
			var count uint64
			err := objs.PktCount.Lookup(uint32(0), &count)
			if err != nil {
				log.Fatal("Map lookup:", err)
			}
			log.Printf("Received %d packets", count)
		case <-stop:
			log.Print("Received signal, exiting..")
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

	// First, try to look for eth0 (common in containers/VMs)
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
