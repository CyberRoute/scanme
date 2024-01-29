<p align="center">
  <a href="https://github.com/CyberRoute/scanme/releases/latest"><img alt="Release" src="https://img.shields.io/github/release/CyberRoute/scanme.svg?style=flat-square"></a>
  <a href="https://github.com/CyberRoute/scanme/actions/workflows/golangci-lint.yml/badge.svg?branch=main"><img alt="golangci-lint" src="https://img.shields.io/badge/golangci-lint-brightgreen.svg?style=flat"></a>
  <a href="https://goreportcard.com/badge/github.com/CyberRoute/scanme"><img alt="Go Report" src="https://img.shields.io/badge/go%20report-A+-brightgreen.svg?style=flat"></a>
  <a href="https://github.com/CyberRoute/scanme/blob/main/LICENSE"><img alt="Software License" src="https://img.shields.io/badge/license-GPL3-brightgreen.svg?style=flat"></a>
  <a href="http://godoc.org/github.com/CyberRoute/scanme"> <img alt="Docs" src="https://img.shields.io/badge/godoc-reference-blue.svg?style=flat-square"></a>
</p>

## Scanme :eye:

Scanme is a Go package for network scanning using the GoPacket library. It allows scanning a single IP address for open ports.
This is not an attempt to rewrite **nmap**, probably the most popular scan, but learn more deeply about network scanning technics, parallelism
is not yet implemented but will be coming soon. Despite scanning the 65k tcp ports serially it is pretty fast if compared with:

```bash
nmap -vvv -sS -p 1-65535 <ip-tagert>
nmap -vvv -sT  -p 1-65535 <ip-tagert>
```

## Features

- **SYN Scan:** Perform SYN scans to identify open ports on a target host (supports IPv4 and IPv6).
- **Connect Scan:** Perform a full TCP handshake on a target host (supports IPv4 and IPv6).
- **ICMP Echo Request:** Send ICMP Echo Requests to discover live hosts on the network.

## Example Simple scanner
<div align="center">
    <img src="/img/scanme.png" width="800px"</img> 
</div>

## Installation

- On Linux, install `libpcap` 

```bash
go get -u github.com/CyberRoute/scanme
```

## Usage

```go
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
		log.Printf("Port %v is %v", port, service)
	}

	defer scanner.Close()

	elapsedTime := time.Since(startTime)
	log.Printf("Execution time: %s", elapsedTime)
}
```

## Sample scan
```
alessandro@xps:~/Development/scanme$ sudo go run main.go -ip 172.16.168.131
[sudo] password for alessandro: 
2024/01/11 15:04:53 scanning ip 172.16.168.131 with interface vmnet8, gateway <nil>, src 172.16.168.1
2024/01/11 15:04:53 ICMP Echo Reply received from 172.16.168.131
2024/01/11 15:04:54 last port scanned for 172.16.168.131 dst port 65535 assuming we've seen all we can
2024/01/11 15:04:54 Port 445(microsoft-ds) is open
2024/01/11 15:04:54 Port 139(netbios-ssn) is open
2024/01/11 15:04:54 Port 143(imap) is open
2024/01/11 15:04:54 Port 443(https) is open
2024/01/11 15:04:54 Port 5001(commplex-link) is open
2024/01/11 15:04:54 Port 8080(http-alt) is open
2024/01/11 15:04:54 Port 8081(sunproxyadmin) is open
2024/01/11 15:04:54 Port 22(ssh) is open
2024/01/11 15:04:54 Port 80(http) is open
2024/01/11 15:04:54 Execution time: 963.973315ms
```

## Contribute
Contributions are welcome! If you find any issues or have suggestions for improvement, please create an issue or pull request.

## License
Scanme is developed by Alessandro Bresciani with some help from various projects and released with GPL license.

## Acknowledgments
Inspired by and wanting to improve this https://github.com/google/gopacket/blob/master/examples/synscan/main.go
Technical details checked here https://nmap.org/book/synscan.html and obviously https://github.com/nmap/nmap


