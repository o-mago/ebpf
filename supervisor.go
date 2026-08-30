package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
)

type Service struct {
	Name    string
	Command string
	Args    []string
	Cwd     string
	Env     []string
	Color   string
}

type BuildCommand struct {
	Dir  string
	Args []string
}

const (
	Reset   = "\033[0m"
	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Magenta = "\033[35m"
	Cyan    = "\033[36m"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run supervisor.go [packet-counter|otel|firewall|service-mesh]")
		os.Exit(1)
	}

	project := os.Args[1]
	wd, err := os.Getwd()
	if err != nil {
		fmt.Printf("Failed to get working directory: %v\n", err)
		os.Exit(1)
	}

	var services []Service
	var buildCmds []BuildCommand

	switch project {
	case "packet-counter":
		buildCmds = []BuildCommand{
			{Dir: "packet-counter", Args: []string{"go", "generate"}},
			{Dir: "packet-counter", Args: []string{"go", "build", "-o", "bin/packet-counter"}},
		}
		services = []Service{
			{
				Name:    "packet-counter",
				Command: "sudo",
				Args:    []string{"./bin/packet-counter"},
				Cwd:     filepath.Join(wd, "packet-counter"),
				Color:   Cyan,
			},
		}

	case "otel":
		buildCmds = []BuildCommand{
			{Dir: "otel/otel-tracer", Args: []string{"go", "generate"}},
			{Dir: "otel/otel-profiler", Args: []string{"go", "generate"}},
			{Dir: "otel/api-server", Args: []string{"go", "build", "-o", "bin/api-server"}},
			{Dir: "otel/otel-tracer", Args: []string{"go", "build", "-o", "bin/otel-tracer"}},
			{Dir: "otel/otel-profiler", Args: []string{"go", "build", "-o", "bin/otel-profiler"}},
		}
		services = []Service{
			{
				Name:    "api-server",
				Command: "./bin/api-server",
				Cwd:     filepath.Join(wd, "otel/api-server"),
				Color:   Green,
			},
			{
				Name:    "otel-tracer",
				Command: "sudo",
				Args:    []string{"./bin/otel-tracer", "../api-server/bin/api-server"},
				Cwd:     filepath.Join(wd, "otel/otel-tracer"),
				Color:   Cyan,
			},
			{
				Name:    "otel-profiler",
				Command: "sudo",
				Args:    []string{"./bin/otel-profiler"},
				Cwd:     filepath.Join(wd, "otel/otel-profiler"),
				Color:   Yellow,
			},
		}

	case "firewall":
		buildCmds = []BuildCommand{
			{Dir: "firewall/ebpf", Args: []string{"go", "generate"}},
			{Dir: "firewall/service", Args: []string{"go", "build", "-o", "bin/service"}},
			{Dir: "firewall/ebpf", Args: []string{"go", "build", "-o", "bin/ebpf-mesh"}},
		}
		services = []Service{
			{
				Name:    "service-3",
				Command: "./bin/service",
				Args:    []string{"3"},
				Cwd:     filepath.Join(wd, "firewall/service"),
				Color:   Green,
			},
			{
				Name:    "service-1",
				Command: "./bin/service",
				Args:    []string{"1"},
				Cwd:     filepath.Join(wd, "firewall/service"),
				Color:   Cyan,
			},
			{
				Name:    "service-2",
				Command: "./bin/service",
				Args:    []string{"2"},
				Cwd:     filepath.Join(wd, "firewall/service"),
				Color:   Yellow,
			},
			{
				Name:    "ebpf-firewall",
				Command: "sudo",
				Args:    []string{"./bin/ebpf-mesh"},
				Cwd:     filepath.Join(wd, "firewall/ebpf"),
				Color:   Red,
			},
		}

	case "service-mesh":
		buildCmds = []BuildCommand{
			{Dir: "service-mesh/ebpf", Args: []string{"go", "generate"}},
			{Dir: "service-mesh/service", Args: []string{"go", "build", "-o", "bin/service"}},
			{Dir: "service-mesh/ebpf", Args: []string{"go", "build", "-o", "bin/ebpf-mesh"}},
		}
		services = []Service{
			{
				Name:    "service-3",
				Command: "./bin/service",
				Args:    []string{"3"},
				Cwd:     filepath.Join(wd, "service-mesh/service"),
				Color:   Green,
			},
			{
				Name:    "service-4",
				Command: "./bin/service",
				Args:    []string{"4"},
				Cwd:     filepath.Join(wd, "service-mesh/service"),
				Color:   Magenta,
			},
			{
				Name:    "service-1",
				Command: "./bin/service",
				Args:    []string{"1"},
				Cwd:     filepath.Join(wd, "service-mesh/service"),
				Color:   Cyan,
			},
			{
				Name:    "service-2",
				Command: "./bin/service",
				Args:    []string{"2"},
				Cwd:     filepath.Join(wd, "service-mesh/service"),
				Color:   Yellow,
			},
			{
				Name:    "control-panel",
				Command: "sudo",
				Args:    []string{"-E", "./bin/ebpf-mesh"},
				Cwd:     filepath.Join(wd, "service-mesh/ebpf"),
				Env:     []string{"LOG_ONLY=true"},
				Color:   Red,
			},
		}

	case "service-mesh-services":
		buildCmds = []BuildCommand{
			{Dir: "service-mesh/ebpf", Args: []string{"go", "generate"}},
			{Dir: "service-mesh/service", Args: []string{"go", "build", "-o", "bin/service"}},
			{Dir: "service-mesh/ebpf", Args: []string{"go", "build", "-o", "bin/ebpf-mesh"}},
		}
		services = []Service{
			{
				Name:    "service-3",
				Command: "./bin/service",
				Args:    []string{"3"},
				Cwd:     filepath.Join(wd, "service-mesh/service"),
				Color:   Green,
			},
			{
				Name:    "service-4",
				Command: "./bin/service",
				Args:    []string{"4"},
				Cwd:     filepath.Join(wd, "service-mesh/service"),
				Color:   Magenta,
			},
			{
				Name:    "service-1",
				Command: "./bin/service",
				Args:    []string{"1"},
				Cwd:     filepath.Join(wd, "service-mesh/service"),
				Color:   Cyan,
			},
			{
				Name:    "service-2",
				Command: "./bin/service",
				Args:    []string{"2"},
				Cwd:     filepath.Join(wd, "service-mesh/service"),
				Color:   Yellow,
			},
		}

	default:
		fmt.Printf("Unknown project: %s. Supported: packet-counter, otel, firewall, service-mesh, service-mesh-services\n", project)
		os.Exit(1)
	}

	// 1. Run Generate & Build commands sequentially in their target directories
	fmt.Printf("[supervisor] Preparing project %s (running code generate & compilation)...\n", project)
	for _, bCmd := range buildCmds {
		cmd := exec.Command(bCmd.Args[0], bCmd.Args[1:]...)
		cmd.Dir = filepath.Join(wd, bCmd.Dir)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Printf("[supervisor] Build failed in dir %s: %v\n", bCmd.Dir, err)
			os.Exit(1)
		}
	}
	fmt.Println("[supervisor] Build completed successfully. Starting services...")

	// 2. Start services in parallel
	var wg sync.WaitGroup
	var runningCmds []*exec.Cmd
	var mutex sync.Mutex

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle Graceful Shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\n[supervisor] Received interrupt signal. Terminating all processes...")
		cancel()

		mutex.Lock()
		for _, cmd := range runningCmds {
			if cmd.Process != nil {
				// Kill the entire process group (negative PID)
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			}
		}
		mutex.Unlock()
	}()

	for _, svc := range services {
		wg.Add(1)
		go func(s Service) {
			defer wg.Done()

			cmd := exec.CommandContext(ctx, s.Command, s.Args...)
			cmd.Dir = s.Cwd
			// Set Process Group ID to allow killing all spawned sub-processes together
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

			// Configure Environment Variables
			if len(s.Env) > 0 {
				cmd.Env = append(os.Environ(), s.Env...)
			}

			stdout, err := cmd.StdoutPipe()
			if err != nil {
				fmt.Printf("[%s] Failed to get stdout pipe: %v\n", s.Name, err)
				return
			}
			stderr, err := cmd.StderrPipe()
			if err != nil {
				fmt.Printf("[%s] Failed to get stderr pipe: %v\n", s.Name, err)
				return
			}

			if err := cmd.Start(); err != nil {
				fmt.Printf("[%s] Failed to start command: %v\n", s.Name, err)
				return
			}

			mutex.Lock()
			runningCmds = append(runningCmds, cmd)
			mutex.Unlock()

			// Prefix reader
			prefix := fmt.Sprintf("%s[%s]%s ", s.Color, s.Name, Reset)
			var logWg sync.WaitGroup

			readPipe := func(r io.Reader) {
				defer logWg.Done()
				scanner := bufio.NewScanner(r)
				for scanner.Scan() {
					fmt.Printf("%s%s\n", prefix, scanner.Text())
				}
			}

			logWg.Add(2)
			go readPipe(stdout)
			go readPipe(stderr)

			logWg.Wait()
			_ = cmd.Wait()
		}(svc)
	}

	wg.Wait()
	fmt.Println("[supervisor] All services terminated.")
}
