## Scanme

Scanme is a Go package for network scanning using the GoPacket library. It allows scanning a single IP address for open ports using SYN scans.
This is not an attempt to rewrite **nmap -sS**, probably the most popular scan option, but learn more deeply about network scanning technics, parallelism
is not yet implemented but will be coming soon. Despite scanning the 65k tcp ports serially it is pretty fast if compared with:

```bash
sudo nmap -vvv -sS -p 1-65535 <ip-tagert>
```

## Features

- **SYN Scan:** Perform SYN scans to identify open ports on a target host.
- **ICMP Echo Request:** Send ICMP Echo Requests to discover live hosts on the network.

## Example Simple scanner
<div align="center">
    <img src="/img/scanme.png" width="800px"</img> 
</div>

## Installation

```bash
go get -u github.com/CyberRoute/scanme
```

## Usage

```go
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

## Sample scan
```bash
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
Bruter is developed by Alessandro Bresciani with some help from various projects and released with GPL license.

## Acknowledgments
Inspired by and wanting to improve this https://github.com/google/gopacket/blob/master/examples/synscan/main.go
Technical details checked here https://nmap.org/book/synscan.html and obviously https://github.com/nmap/nmap


