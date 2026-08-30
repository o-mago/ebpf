package main

import (
	"fmt"
	"log/slog"
	"math/rand"
	"net/http"
	"os"
	"time"
)

//go:noinline
func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"UP"}`))
}

//go:noinline
func handleWork(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	// Simulate heavy heap allocations (creating strings and slices dynamically)
	// We allocate a slice of strings to simulate garbage collection and heap pressure
	var memoryLoad []string
	for i := 0; i < 1000; i++ {
		// Hard limit of 1 second
		if time.Since(startTime) >= 1*time.Second {
			break
		}
		// Create formatted strings of around ~100 bytes to force heap allocations
		str := fmt.Sprintf("Heap allocation block #%d: simulating memory allocation with some dummy string contents to populate size", i)
		memoryLoad = append(memoryLoad, str)
	}

	// Simulate busy CPU work (varying latency between 10ms and 100ms)
	// We use a busy loop instead of time.Sleep so that the OS thread is not yielded.
	durationMs := 10 + rand.Intn(90)
	deadline := time.Now().Add(time.Duration(durationMs) * time.Millisecond)
	for time.Now().Before(deadline) {
		// Hard limit of 1 second
		if time.Since(startTime) >= 1*time.Second {
			break
		}
	}

	// Format response using the allocated slice to prevent compiler optimization
	responseMsg := fmt.Sprintf("work completed successfully: processed %d allocations", len(memoryLoad))

	w.WriteHeader(http.StatusOK)
	w.Write(fmt.Appendf(nil, `{"status":%q}`, responseMsg))
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", handleHealth)
	mux.HandleFunc("GET /api/work", handleWork)

	serverAddr := ":8080"
	slog.Info("Starting target API Server", "address", serverAddr)
	if err := http.ListenAndServe(serverAddr, mux); err != nil {
		slog.Error("Server failed to start", "error", err)
		os.Exit(1)
	}
}
