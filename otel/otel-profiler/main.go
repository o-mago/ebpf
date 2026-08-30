//go:build linux

package main

import (
	"debug/elf"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// Using bpf2go auto-generated types:
// - profilerAllocMetrics (for mem_metrics)
// - profilerStackAlloc (for stack_allocs)

type Symbol struct {
	Name  string
	Value uint64
}

type stackEntry struct {
	Bytes uint64
	Count uint64
	IPs   [20]uint64
}

type cpuStackEntry struct {
	Count uint64
	IPs   [20]uint64
}

type SymbolResolver struct {
	symbols []Symbol
}

func NewSymbolResolver(pid int) (*SymbolResolver, error) {
	elfFile, err := elf.Open(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return nil, err
	}
	defer elfFile.Close()

	elfSyms, err := elfFile.Symbols()
	if err != nil {
		return nil, fmt.Errorf("failed to read elf symbols: %w", err)
	}

	var symbols []Symbol
	for _, sym := range elfSyms {
		if sym.Name != "" {
			symbols = append(symbols, Symbol{
				Name:  sym.Name,
				Value: sym.Value,
			})
		}
	}

	sort.Slice(symbols, func(i, j int) bool {
		return symbols[i].Value < symbols[j].Value
	})

	return &SymbolResolver{symbols: symbols}, nil
}

func (r *SymbolResolver) Resolve(ip uint64) string {
	if r == nil || len(r.symbols) == 0 {
		return fmt.Sprintf("0x%x", ip)
	}

	idx := sort.Search(len(r.symbols), func(i int) bool {
		return r.symbols[i].Value > ip
	})

	if idx > 0 {
		sym := r.symbols[idx-1]
		// Verify that the IP is within a reasonable offset of the symbol (e.g. 500KB)
		if ip >= sym.Value && ip-sym.Value < 500000 {
			return sym.Name
		}
	}

	return fmt.Sprintf("0x%x", ip)
}

func main() {
	if len(os.Args) < 2 {
		slog.Error("Missing argument", "usage", fmt.Sprintf("%s <target-pid>", os.Args[0]))
		os.Exit(1)
	}

	targetPID, err := strconv.Atoi(os.Args[1])
	if err != nil {
		slog.Error("Invalid target PID", "error", err)
		os.Exit(1)
	}

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		slog.Error("Failed to remove memlock limit", "error", err)
		os.Exit(1)
	}

	// Load BPF spec to rewrite the target_pid global constant before load
	spec, err := loadProfiler()
	if err != nil {
		slog.Error("Failed to load eBPF specs", "error", err)
		os.Exit(1)
	}

	// Rewrite target_pid global variable
	if err := spec.Variables["target_pid"].Set(uint32(targetPID)); err != nil {
		slog.Error("Failed to set target_pid spec constant", "error", err)
		os.Exit(1)
	}

	// Load objects into kernel using LoadAndAssign
	var objs profilerObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		slog.Error("Failed to load eBPF objects", "error", err)
		os.Exit(1)
	}
	defer objs.Close()

	// Initialize Symbol Resolver for resolving stack traces
	resolver, err := NewSymbolResolver(targetPID)
	if err != nil {
		slog.Warn("Failed to initialize symbol resolver, stack traces will display raw addresses", "error", err)
	}

	// Locate binary path using /proc/[pid]/exe
	binaryPath := fmt.Sprintf("/proc/%d/exe", targetPID)
	ex, err := link.OpenExecutable(binaryPath)
	if err != nil {
		slog.Error("Failed to open target executable via symlink", "path", binaryPath, "error", err)
		os.Exit(1)
	}

	// Hook runtime.mallocgc with a uprobe to profile memory allocations
	mallocProbe, err := ex.Uprobe("runtime.mallocgc", objs.TraceMalloc, nil)
	if err != nil {
		slog.Error("Failed to attach runtime.mallocgc uprobe", "error", err)
		os.Exit(1)
	}
	defer mallocProbe.Close()

	// Set up CPU Sampling via Perf Events on each CPU core
	numCPU, err := ebpf.PossibleCPU()
	if err != nil {
		slog.Error("Failed to get CPU count", "error", err)
		os.Exit(1)
	}

	// 99Hz sampling rate (99 samples per second per CPU)
	attr := &unix.PerfEventAttr{
		Type:   unix.PERF_TYPE_SOFTWARE,
		Config: unix.PERF_COUNT_SW_CPU_CLOCK,
		Bits:   unix.PerfBitDisabled | unix.PerfBitFreq,
		Sample: 99,
	}

	var perfFDs []int
	defer func() {
		for _, fd := range perfFDs {
			_ = unix.Close(fd)
		}
	}()

	for cpu := 0; cpu < numCPU; cpu++ {
		// Open perf event for all PIDs on this CPU (-1 for PID to trace everyone, we filter by target_pid in C)
		fd, err := unix.PerfEventOpen(attr, -1, cpu, -1, 0)
		if err != nil {
			slog.Error("Failed to open perf event", "cpu", cpu, "error", err)
			os.Exit(1)
		}
		perfFDs = append(perfFDs, fd)

		// Attach eBPF program to the perf event using ioctl
		if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_SET_BPF, objs.DoCpuSample.FD()); err != nil {
			slog.Error("Failed to attach BPF program to perf event", "cpu", cpu, "error", err)
			os.Exit(1)
		}

		// Enable the perf event using ioctl
		if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
			slog.Error("Failed to enable perf event", "cpu", cpu, "error", err)
			os.Exit(1)
		}
	}

	slog.Info("OTel Profiler successfully attached", "target_pid", targetPID, "cpus", numCPU)

	// Periodically read metrics from maps and print them
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var lastCPUSamples uint64
	var lastAllocBytes uint64
	var lastAllocCount uint64

	fmt.Println("\nWaiting for metrics...")

	for {
		select {
		case <-ticker.C:
			// Read CPU samples map
			var cpuSamples uint64
			if err := objs.CpuSamples.Lookup(uint32(0), &cpuSamples); err != nil {
				slog.Error("Error looking up CPU samples map", "error", err)
			}

			// Read Memory metrics map
			var mem profilerAllocMetrics
			if err := objs.MemMetrics.Lookup(uint32(0), &mem); err != nil {
				slog.Error("Error looking up memory metrics map", "error", err)
			}

			// Read Stack allocations
			var stackID int32
			var sa profilerStackAlloc
			var entries []stackEntry

			iter := objs.StackAllocs.Iterate()
			for iter.Next(&stackID, &sa) {
				var ips [20]uint64
				if err := objs.StackTraces.Lookup(stackID, &ips); err == nil {
					entries = append(entries, stackEntry{
						Bytes: sa.Bytes,
						Count: sa.Count,
						IPs:   ips,
					})
				}
			}

			// Sort stack allocations by bytes descending
			sort.Slice(entries, func(i, j int) bool {
				return entries[i].Bytes > entries[j].Bytes
			})

			// Read CPU stack samples
			var cpuStackID int32
			var cpuCount uint64
			var cpuEntries []cpuStackEntry

			iterCPU := objs.CpuStackSamples.Iterate()
			for iterCPU.Next(&cpuStackID, &cpuCount) {
				var ips [20]uint64
				if err := objs.StackTraces.Lookup(cpuStackID, &ips); err == nil {
					cpuEntries = append(cpuEntries, cpuStackEntry{
						Count: cpuCount,
						IPs:   ips,
					})
				}
			}

			// Sort CPU stack samples by tick count descending
			sort.Slice(cpuEntries, func(i, j int) bool {
				return cpuEntries[i].Count > cpuEntries[j].Count
			})

			// Calculate differentials
			deltaCPU := cpuSamples - lastCPUSamples
			deltaBytes := uint64(mem.TotalBytes) - lastAllocBytes
			deltaCount := uint64(mem.AllocCount) - lastAllocCount

			lastCPUSamples = cpuSamples
			lastAllocBytes = uint64(mem.TotalBytes)
			lastAllocCount = uint64(mem.AllocCount)

			// Approximate CPU utilization:
			// Max possible ticks per second across all cores = 99 * numCPU
			maxTicks := float64(99 * numCPU)
			cpuUtilization := (float64(deltaCPU) / maxTicks) * 100.0
			if cpuUtilization > 100.0 {
				cpuUtilization = 100.0
			}

			printProfilerMetrics(targetPID, cpuUtilization, deltaCPU, mem.TotalBytes, deltaBytes, mem.AllocCount, deltaCount)
			printTopCPU(resolver, cpuEntries, cpuSamples)
			printTopAllocators(resolver, entries)

		case sig := <-stop:
			slog.Info("Profiler shutting down gracefully", "signal", sig.String())
			return
		}
	}
}

func printProfilerMetrics(pid int, cpuUtil float64, cpuTicks uint64, totalAllocBytes uint64, deltaBytes uint64, totalAllocCount uint64, deltaCount uint64) {
	fmt.Println()
	fmt.Println("----------------- SIMULATED OpenTelemetry Profile -----------------")
	fmt.Printf("Target PID:          %d\n", pid)
	fmt.Printf("Timestamp:           %s\n", time.Now().Format(time.RFC3339))
	fmt.Println("\n[CPU Metrics]")
	fmt.Printf("  CPU Utilization:   %.2f%%\n", cpuUtil)
	fmt.Printf("  CPU Samples/sec:   %d ticks\n", cpuTicks)
	fmt.Println("\n[Memory Heap Allocation Metrics (mallocgc)]")
	fmt.Printf("  Allocated Rate:    %.2f MB/sec\n", float64(deltaBytes)/(1024*1024))
	fmt.Printf("  Allocation Rate:   %d allocs/sec\n", deltaCount)
	fmt.Printf("  Total Heap Alloc:  %.2f MB (cumulative)\n", float64(totalAllocBytes)/(1024*1024))
	fmt.Printf("  Total Heap Count:  %d allocations (cumulative)\n", totalAllocCount)
}

func printTopCPU(r *SymbolResolver, entries []cpuStackEntry, totalCPUTicks uint64) {
	fmt.Println("\n[Top CPU Consuming Stack Traces (Hottest Paths)]")
	limit := 3
	if len(entries) < limit {
		limit = len(entries)
	}

	if limit == 0 || totalCPUTicks == 0 {
		fmt.Println("  No CPU samples recorded yet.")
	}

	for i := 0; i < limit; i++ {
		entry := entries[i]
		percentage := (float64(entry.Count) / float64(totalCPUTicks)) * 100.0
		fmt.Printf("  %d. %.2f%% of process CPU time (%d ticks)\n", i+1, percentage, entry.Count)

		// Print resolved call stack
		framesPrinted := 0
		for _, ip := range entry.IPs {
			if ip == 0 {
				break
			}
			symbolName := r.Resolve(ip)
			if symbolName != "" {
				fmt.Printf("     -> %s\n", symbolName)
				framesPrinted++
			}
		}
		if framesPrinted == 0 {
			fmt.Println("     -> [No user frames captured]")
		}
	}
}

func printTopAllocators(r *SymbolResolver, entries []stackEntry) {
	fmt.Println("\n[Top Heap Allocating Stack Traces]")
	limit := 3
	if len(entries) < limit {
		limit = len(entries)
	}

	if limit == 0 {
		fmt.Println("  No heap allocations recorded yet.")
	}

	for i := 0; i < limit; i++ {
		entry := entries[i]
		fmt.Printf("  %d. %.2f MB (%d allocations)\n", i+1, float64(entry.Bytes)/(1024*1024), entry.Count)

		// Print resolved call stack
		framesPrinted := 0
		for _, ip := range entry.IPs {
			if ip == 0 {
				break
			}
			symbolName := r.Resolve(ip)
			if symbolName != "" {
				fmt.Printf("     -> %s\n", symbolName)
				framesPrinted++
			}
		}
		if framesPrinted == 0 {
			fmt.Println("     -> [No user frames captured]")
		}
	}
	fmt.Println("-------------------------------------------------------------------")
	fmt.Println()
}
