// main.go
package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf xdp.c

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
)

func main() {
	// 1. Load pre-compiled eBPF programs into the kernel
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	// 2. Look up the network interface. 
	// We use "lo" (loopback) for local testing. Change to "eth0" or "wlan0" if needed.
	ifaceName := "lo"
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("Failed to look up network interface %q: %s", ifaceName, err)
	}

	// 3. Attach the eBPF program to the XDP hook on the interface
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.Ping, // "Ping" matches your C function name `int ping(...)`
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("Could not attach XDP program: %s", err)
	}
	defer l.Close()

	log.Printf("Successfully attached XDP program to interface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program...")

	// 4. Wait for an interrupt signal to exit cleanly
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	<-stopper
	log.Println("Detaching XDP program and exiting.")
}