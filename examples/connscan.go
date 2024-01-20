package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/CyberRoute/scanme/scanme"
	"github.com/google/gopacket/routing"
)

func main() {
	var targetIP string
	flag.StringVar(&targetIP, "ip", "", "Target IP address to scan")
	flag.Parse()

	if targetIP == "" {
		fmt.Println("Usage: sudo go run main.go -ip <target_ip>")
		os.Exit(1)
	}

	router, err := routing.New()
	if err != nil {
		log.Fatal("Error creating router:", err)
	}

	ip := net.ParseIP(targetIP)
	if ip == nil {
		log.Fatal("Invalid target IP address")
	}

	startTime := time.Now() // Record the start time

	// Create a scanner
	scanner, err := scanme.NewScanner(ip, router)
	if err != nil {
		log.Fatal("Error creating scanner:", err)
	}
	defer scanner.Close()

	// Perform connection scan
	openPorts, err := scanner.ConnScan()
	if err != nil {
		log.Fatal("Error during connection scan:", err)
	}

	// Print results
	for port, service := range openPorts {
		log.Printf("Port %d%s\n", port, service)
	}
	elapsedTime := time.Since(startTime)
	log.Printf("Execution time: %s", elapsedTime)
}
