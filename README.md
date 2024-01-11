## Scanme

Scanme is a Go package for network scanning using the GoPacket library. It allows scanning a single IP address for open ports using SYN scans.

## Features

- **SYN Scan:** Perform SYN scans to identify open ports on a target host.
- **ICMP Echo Request:** Send ICMP Echo Requests to discover live hosts on the network.

## Example Simple scanner
<div align="center">
    <img src="/img/scanme.png" width="800px"</img> 
</div>

## Installation

```
go get -u github.com/CyberRoute/scanme
```

## Usage

```
package main

import (
	"log"
	"net"

	"github.com/CyberRoute/scanme"
	"github.com/google/gopacket/routing"
)

func main() {
	// Create a new scanner for the target IP address
	ip := net.ParseIP("192.168.1.1")
	router, err := routing.New()
	if err != nil {
		log.Fatal(err)
	}

	scanner, err := scanme.NewScanner(ip, router)
	if err != nil {
		log.Fatal(err)
	}
	defer scanner.Close()

	// Perform SYN scan and get open ports
	openPorts, err := scanner.Synscan()
	if err != nil {
		log.Fatal(err)
	}

	// Process open ports
	for port, service := range openPorts {
		log.Printf("Port %v is %v", port, service)
	}
}
```

## Contribute
Contributions are welcome! If you find any issues or have suggestions for improvement, please create an issue or pull request.

## Acknowledgments
Inspired by and wanting to improve this https://github.com/google/gopacket/blob/master/examples/synscan/main.go


