//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go mesh mesh.c

type firewallEvent struct {
	PID     uint32
	Action  uint32 // 0 for Block, 1 for Allow
	DstIP   uint32
	DstPort uint32
}

func findService2PID() (int, error) {
	files, err := os.ReadDir("/proc")
	if err != nil {
		return 0, err
	}

	for _, f := range files {
		if !f.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(f.Name())
		if err != nil {
			continue
		}

		// Read cmdline of the process
		cmdlineBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if err != nil {
			continue
		}

		cmdline := string(cmdlineBytes)
		// Process arguments are null-terminated inside /proc/[pid]/cmdline
		parts := strings.Split(cmdline, "\x00")
		if len(parts) < 2 {
			continue
		}

		// Check if the binary filename is "service" and its first parameter is "2"
		binaryName := filepath.Base(parts[0])
		if binaryName == "service" && parts[1] == "2" {
			return pid, nil
		}
	}

	return 0, fmt.Errorf("process 'service 2' not found")
}

func getComm(pid uint32) string {
	commBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(commBytes))
}

func ipToString(ipVal uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ipVal),
		byte(ipVal>>8),
		byte(ipVal>>16),
		byte(ipVal>>24),
	)
}

func main() {
	var pidToBlock int
	var err error

	if len(os.Args) >= 2 {
		pidToBlock, err = strconv.Atoi(os.Args[1])
		if err != nil {
			slog.Error("Invalid PID argument", "error", err)
			os.Exit(1)
		}
	} else {
		// Auto-detect Service 2 PID directly from /proc
		pidToBlock, err = findService2PID()
		if err != nil {
			slog.Error("Failed to auto-detect Service 2 PID. Is it running?", "error", err)
			os.Exit(1)
		}
		slog.Info("Auto-detected Service 2 PID", "pid", pidToBlock)
	}

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		slog.Error("Failed to remove memlock limit", "error", err)
		os.Exit(1)
	}

	// Load BPF objects
	var objs meshObjects
	if err := loadMeshObjects(&objs, nil); err != nil {
		slog.Error("Failed to load eBPF objects", "error", err)
		os.Exit(1)
	}
	defer objs.Close()

	// Add Service 2 PID to blocked_pids map
	pidKey := uint32(pidToBlock)
	val := uint32(1)
	if err := objs.BlockedPids.Put(&pidKey, &val); err != nil {
		slog.Error("Failed to add PID to blocked list map", "error", err)
		os.Exit(1)
	}
	slog.Info("Successfully added PID to eBPF block list", "pid", pidToBlock)

	// Open cgroup root
	cgroupPath := "/sys/fs/cgroup"
	cgroupFile, err := os.Open(cgroupPath)
	if err != nil {
		slog.Error("Failed to open cgroup path", "path", cgroupPath, "error", err)
		os.Exit(1)
	}
	defer cgroupFile.Close()

	// Attach BPF program to cgroup root connect4 hook
	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupFile.Name(),
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: objs.CheckConnect,
	})
	if err != nil {
		slog.Error("Failed to attach eBPF program to cgroup root", "error", err)
		os.Exit(1)
	}
	defer l.Close()

	slog.Info("eBPF Service Mesh Firewall attached successfully to cgroup root!")
	slog.Info("All TCP IPv4 connections to port 8083 from blocked PID will be denied.")

	// Open Ring Buffer reader to read audit events
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		slog.Error("Failed to create ring buffer reader", "error", err)
		os.Exit(1)
	}
	defer rd.Close()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	// Start a background loop to process and print connection log rules
	go func() {
		var event firewallEvent
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				slog.Error("Failed reading from ring buffer", "error", err)
				continue
			}

			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				slog.Error("Failed parsing event record", "error", err)
				continue
			}

			comm := getComm(event.PID)
			ipStr := ipToString(event.DstIP)
			destAddr := fmt.Sprintf("%s:%d", ipStr, event.DstPort)

			if event.Action == 0 {
				slog.Warn("[FIREWALL BLOCK]", "pid", event.PID, "process", comm, "destination", destAddr, "action", "DENIED")
			} else {
				slog.Info("[FIREWALL ALLOW]", "pid", event.PID, "process", comm, "destination", destAddr, "action", "ALLOWED")
			}
		}
	}()

	sig := <-stop
	slog.Info("Detaching and shutting down...", "signal", sig.String())
}
