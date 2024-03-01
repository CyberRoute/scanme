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

var (
	targetIP = flag.String("ip", "127.0.0.1", "IP address to bind the web UI server to.")
)

func main() {

	flag.Parse()
	if *targetIP == "" {
		fmt.Println("No ip specified.")
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

	openPorts, err := scanner.Synscan()
	if err != nil {
		log.Fatalf("Unable to scan %v: %v", ip, err)

	}
	// Process open ports
	for port, service := range openPorts {
		var banner string
		var err error
		switch service {
		case "mysql":
			banner, _ = scanme.GrabMysqlBanner(targetIP, int(port))
		default:
			banner = scanme.GrabBanner(targetIP, int(port))
		}
		if err != nil {
			log.Printf("Error grabbing banner for port %d (%s): %v", port, service, err)
			continue
		}
		if banner != "" {
			log.Printf("Port %v %v Version: %s", port, service, banner)
		} else {
			log.Printf("Port %v %v", port, service)
		}
	}

	defer scanner.Close()

	elapsedTime := time.Since(startTime)
	log.Printf("Execution time: %s", elapsedTime)
}
