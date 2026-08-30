package main

import (
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"os"
	"time"
)

type ServiceConfig struct {
	Addr     string
	Version  string
	IsGate   bool
	GateName string
}

var configs = map[string]ServiceConfig{
	"1": {Addr: ":8081", IsGate: true, GateName: "Service-1"},
	"2": {Addr: ":8082", IsGate: true, GateName: "Service-2"},
	"3": {Addr: ":8083", Version: "v1.0.0-stable"},
	"4": {Addr: ":8084", Version: "v2.0.0-canary"},
}

var forwardingClient = &http.Client{
	Transport: &http.Transport{
		DisableKeepAlives: true,
	},
}

// Helper function to forward HTTP requests from Gateway to Backend
func forwardRequest(w http.ResponseWriter, r *http.Request, gatewayName string) {
	destURL := fmt.Sprintf("http://127.0.0.1:8083%s", r.URL.Path)
	slog.Info("Gateway forwarding request", "gateway", gatewayName, "path", r.URL.Path, "destination", destURL)

	resp, err := forwardingClient.Get(destURL)
	if err != nil {
		slog.Error("Forwarding failed", "gateway", gatewayName, "error", err)
		http.Error(w, fmt.Sprintf("Gateway error: call to backend failed: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}

//go:noinline
func handleHealth(w http.ResponseWriter, r *http.Request) {
	version := r.Header.Get("X-Service-Version")
	if version == "" {
		version = "unknown"
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(fmt.Appendf(nil, `{"service":%q,"status":"UP"}`, version))
}

//go:noinline
func handleWork(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	version := r.Header.Get("X-Service-Version")
	if version == "" {
		version = "unknown"
	}

	// Simulate heavy heap allocations
	var memoryLoad []string
	for i := 0; i < 1000; i++ {
		if time.Since(startTime) >= 1*time.Second {
			break
		}
		str := fmt.Sprintf("Service %s allocation block #%d for heap simulation", version, i)
		memoryLoad = append(memoryLoad, str)
	}

	// Simulate busy CPU work
	durationMs := 10 + rand.Intn(90)
	deadline := time.Now().Add(time.Duration(durationMs) * time.Millisecond)
	for time.Now().Before(deadline) {
		if time.Since(startTime) >= 1*time.Second {
			break
		}
	}

	responseMsg := fmt.Sprintf("work completed on %s: processed %d allocations", version, len(memoryLoad))
	w.Header().Set("Content-Type", "application/json")
	w.Write(fmt.Appendf(nil, `{"service":%q,"status":%q}`, version, responseMsg))
}

func main() {
	if len(os.Args) < 2 {
		slog.Error("Usage: service <1|2|3|4>")
		os.Exit(1)
	}
	role := os.Args[1]
	cfg, ok := configs[role]
	if !ok {
		slog.Error("Invalid role. Supported: 1, 2, 3, 4")
		os.Exit(1)
	}

	mux := http.NewServeMux()
	if cfg.IsGate {
		slog.Info("Starting Gateway Service", "role", role, "address", cfg.Addr, "name", cfg.GateName)
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			forwardRequest(w, r, cfg.GateName)
		})
	} else {
		slog.Info("Starting Backend Service", "role", role, "address", cfg.Addr, "version", cfg.Version)
		mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
			r.Header.Set("X-Service-Version", cfg.Version)
			handleHealth(w, r)
		})
		mux.HandleFunc("GET /api/work", func(w http.ResponseWriter, r *http.Request) {
			r.Header.Set("X-Service-Version", cfg.Version)
			handleWork(w, r)
		})
	}

	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 3 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil {
		slog.Error("Service execution terminated", "role", role, "error", err)
		os.Exit(1)
	}
}
