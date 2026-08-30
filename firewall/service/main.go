package main

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		slog.Error("Usage: service <1|2|3>")
		os.Exit(1)
	}
	role := os.Args[1]

	mux := http.NewServeMux()

	switch role {
	case "1":
		slog.Info("Starting Service 1 on :8081 (Allowed to call Service 3)")
		mux.HandleFunc("GET /call", func(w http.ResponseWriter, r *http.Request) {
			slog.Info("Service 1 calling Service 3...")
			resp, err := http.Get("http://127.0.0.1:8083/")
			if err != nil {
				slog.Error("Call failed", "error", err)
				http.Error(w, fmt.Sprintf("Call to Service 3 failed: %v", err), http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			w.Write(body)
		})
		if err := http.ListenAndServe(":8081", mux); err != nil {
			slog.Error("Service 1 failed", "error", err)
		}
	case "2":
		slog.Info("Starting Service 2 on :8082 (Blocked from calling Service 3)")
		mux.HandleFunc("GET /call", func(w http.ResponseWriter, r *http.Request) {
			slog.Info("Service 2 calling Service 3...")
			resp, err := http.Get("http://127.0.0.1:8083/")
			if err != nil {
				slog.Error("Call failed", "error", err)
				http.Error(w, fmt.Sprintf("Call to Service 3 failed: %v", err), http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			w.Write(body)
		})
		if err := http.ListenAndServe(":8082", mux); err != nil {
			slog.Error("Service 2 failed", "error", err)
		}
	case "3":
		slog.Info("Starting Service 3 on :8083 (Receiver)")
		mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
			slog.Info("Service 3 received request!")
			w.Write([]byte(`{"message": "Hello from Service 3!"}`))
		})
		if err := http.ListenAndServe(":8083", mux); err != nil {
			slog.Error("Service 3 failed", "error", err)
		}
	default:
		slog.Error("Invalid role. Must be 1, 2 or 3")
		os.Exit(1)
	}
}
