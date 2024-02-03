package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/CyberRoute/scanme/scanme"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/routing"
)

var (
	targetIP = flag.String("ip", "127.0.0.1", "IP address to bind the web UI server to.")
)

func main() {
	flag.Parse()
	if *targetIP == "" {
		fmt.Println("No IP specified.")
		flag.Usage()
		os.Exit(1)
	}
	targetIP := *targetIP

	ip := net.ParseIP(targetIP)
	if ip == nil {
		log.Fatalf("Invalid IP address: %q", targetIP)
	} else if ip = ip.To4(); ip == nil {
		log.Fatalf("Non-IPv4 address provided: %q", targetIP)
	}

	startTime := time.Now() // Record the start time

	router, err := routing.New()
	if err != nil {
		log.Fatal("Routing error:", err)
	}

	scanner, err := scanme.NewScanner(ip, router)
	if err != nil {
		log.Fatalf("Unable to create scanner for %v: %v", ip, err)
	}

	var wg sync.WaitGroup
	ports := make(chan layers.TCPPort, 100) // Buffered channel to limit concurrency

	// Worker function to scan ports
	portScanner := func() {
		defer wg.Done()
		for port := range ports {
			scanner.SendSynTCP4(targetIP, port)
			//scanner.SendSynTCP4(targetIP, port)
		}
	}

	// Start worker goroutines
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go portScanner()
	}

	// Enqueue ports to be scanned
	for port := 1; port <= 65535; port++ {
		ports <- layers.TCPPort(port)
	}

	close(ports) // Close the channel to signal goroutines to exit

	wg.Wait()

	defer scanner.Close()

	elapsedTime := time.Since(startTime)
	log.Printf("Execution time: %s", elapsedTime)
}
