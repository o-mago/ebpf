package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target amd64,arm64 profiler profiler.c
