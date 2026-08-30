//go:build !linux

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Println("Error: This eBPF application can only compile and run on Linux operating systems.")
	fmt.Println("For macOS development, run the build using a Linux container (e.g. Docker) or a virtual machine (e.g. Lima).")
	os.Exit(1)
}
