package main

import (
	"flag"
	"log"
	"net"
	"github.com/CyberRoute/scanme"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/routing"
)

func main() {
	defer util.Run()()
	router, err := routing.New()
	if err != nil {
		log.Fatal("routing error:", err)
	}
	for _, arg := range flag.Args() {
		var ip net.IP
		if ip = net.ParseIP(arg); ip == nil {
			log.Printf("non-ip target: %q", arg)
			continue
		} else if ip = ip.To4(); ip == nil {
			log.Printf("non-ipv4 target: %q", arg)
			continue
		}
		s, err := scanme.newScanner(ip, router)
		if err != nil {
			log.Printf("unable to create scanner for %v: %v", ip, err)
			continue
		}
		if err := s.synscan(); err != nil {
			log.Printf("unable to scan %v: %v", ip, err)
		}
		s.close()
	}
}
