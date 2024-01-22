package scanme

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/CyberRoute/scanme/utils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/routing"
)

// The type scanner handles scanning a single IP address and is only shared with the packet injector
// iface is the interface to send packets on.
// destination, gateway (if applicable), and source IP addresses to use.
// opts and buf allow us to easily serialize packets in the send()
// method.
type Scanner struct {
	iface        *net.Interface
	dst, gw, src net.IP
	handle       *pcap.Handle
	opts         gopacket.SerializeOptions
	buf          gopacket.SerializeBuffer
}

// newScanner creates a new scanner for a given destination IP address, using
// router to determine how to route packets to that IP.
func NewScanner(ip net.IP, router routing.Router) (*Scanner, error) {
	s := &Scanner{
		dst: ip,
		opts: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		buf: gopacket.NewSerializeBuffer(),
	}

	iface, gw, src, err := router.Route(ip)
	if err != nil {
		return nil, err
	}

	log.Printf("scanning ip %v with interface %v, gateway %v, src %v", ip, iface.Name, gw, src)
	s.gw, s.src, s.iface = gw, src, iface

	handle, err := pcap.OpenLive(iface.Name, 65535, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("error opening pcap handle: %v", err)
	}
	s.handle = handle

	return s, nil
}

// Closes the pcap handle
func (s *Scanner) Close() {
	if s.handle != nil {
		s.handle.Close()
	}
}

// send sends the given layers as a single packet on the network.
func (s *Scanner) send(l ...gopacket.SerializableLayer) error {
	if err := gopacket.SerializeLayers(s.buf, s.opts, l...); err != nil {
		return err
	}
	return s.handle.WritePacketData(s.buf.Bytes())
}

func (s *Scanner) sendARPRequest() (net.HardwareAddr, error) {
	arpDst := s.dst
	if s.gw != nil {
		arpDst = s.gw
	}
	handle, err := pcap.OpenLive(s.iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}

	// Set a BPF filter to capture only ARP replies destined for our source IP
	bpfFilter := fmt.Sprintf("arp and ether dst %s", s.iface.HardwareAddr)
	if err := handle.SetBPFFilter(bpfFilter); err != nil {
		return nil, err
	}

	defer handle.Close()
	// Prepare the layers to send for an ARP request.
	eth := layers.Ethernet{
		SrcMAC:       s.iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(s.iface.HardwareAddr),
		SourceProtAddress: []byte(s.src),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(arpDst),
	}

	// Send a single ARP request packet (we never retry a send, since this
	// SerializeLayers clears the given write buffer, then writes all layers
	// into it so they correctly wrap each other. Note that by clearing the buffer,
	// it invalidates all slices previously returned by w.Bytes()

	if err := s.send(&eth, &arp); err != nil {
		return nil, err
	}
	for {
		data, _, err := handle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		} else if err != nil {
			return net.HardwareAddr{}, err
		}

		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &arp)
		decoded := []gopacket.LayerType{}
		//nolint:staticcheck // SA9003 ignore this!
		if err := parser.DecodeLayers(data, &decoded); err != nil {
			// This branch is intentionally left empty (SA9003).
			// Errors here are due to the decoder, and not all layers are implemented.
			// Uncomment the next line to print the error if needed.
		}

		for _, layerType := range decoded {
			switch layerType {
			case layers.LayerTypeEthernet:
				if net.IP(arp.SourceProtAddress).Equal(net.IP(arpDst)) {
					return net.HardwareAddr(arp.SourceHwAddress), nil
				}
			}
		}
	}
}

func getFreeTCPPort() (layers.TCPPort, error) {
	// Use the library or function that returns a free TCP port as an int.
	tcpport, err := utils.GetFreeTCPPort()
	if err != nil {
		return 0, err
	}
	return layers.TCPPort(tcpport), nil
}

func (s *Scanner) sendICMPEchoRequest() error {
	mac, err := s.sendARPRequest()
	if err != nil {
		return err
	}
	eth := layers.Ethernet{
		SrcMAC:       s.iface.HardwareAddr, // Replace with your source MAC address
		DstMAC:       mac,                  // Broadcast MAC for ICMP
		EthernetType: layers.EthernetTypeIPv4,
	}

	// Prepare IP layer
	ip4 := layers.IPv4{
		SrcIP:    s.src,
		DstIP:    s.dst,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolICMPv4,
	}

	// Prepare ICMP layer for Echo Request
	icmp := layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		Id:       1, // You can set any ID
		Seq:      1, // You can set any sequence number
	}
	if err := s.send(&eth, &ip4, &icmp); err != nil {
		log.Printf("error %v sending ping", err)
	}
	return nil
}

// Synscan performs a SYN port scan on the specified destination IP address using the provided network interface.
// It sends SYN packets to ports [1, 65535] and records open ports in a map. The function employs ARP requests,
// ICMP Echo Requests, and packet capturing to identify open, closed, or filtered ports.
// The function returns a map of open ports along with their status or an error if any occurs during the scan.
func (s *Scanner) Synscan() (map[layers.TCPPort]string, error) {
	openPorts := make(map[layers.TCPPort]string)

	mac, err := s.sendARPRequest()
	if err != nil {
		return nil, err
	}

	tcpport, err := getFreeTCPPort()
	if err != nil {
		return nil, err
	}

	eth := layers.Ethernet{
		SrcMAC:       s.iface.HardwareAddr,
		DstMAC:       mac,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := layers.IPv4{
		SrcIP:    s.src,
		DstIP:    s.dst,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := layers.TCP{
		SrcPort: tcpport,
		DstPort: 0, // will be incremented during the scan
		SYN:     true,
	}

	err = tcp.SetNetworkLayerForChecksum(&ip4)
	if err != nil {
		return nil, err
	}

	ipFlow := gopacket.NewFlow(layers.EndpointIPv4, s.dst, s.src)

	handle, err := pcap.OpenLive(s.iface.Name, 65535, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	// tcp[13] & 0x02 != 0 checks for SYN flag.
	// tcp[13] & 0x10 != 0 checks for ACK flag.
	// tcp[13] & 0x04 != 0 checks for RST flag.
	// this rule should decrease the number of packets captured, still experimenting with this :D
	bpfFilter := "icmp or (tcp and (tcp[13] & 0x02 != 0 or tcp[13] & 0x10 != 0 or tcp[13] & 0x04 != 0))"

	err = handle.SetBPFFilter(bpfFilter)
	if err != nil {
		return nil, err
	}

	defer handle.Close()

	err = s.sendICMPEchoRequest()
	if err != nil {
		return nil, err
	}

	//start := time.Now()

	for {
		// Send one packet per loop iteration until we've sent packets
		// to all of ports [1, 65535].

		if tcp.DstPort < 65535 {
			tcp.DstPort++
			if err := s.send(&eth, &ip4, &tcp); err != nil {
				log.Printf("error sending to port %v: %v", tcp.DstPort, err)
			}
		} else if tcp.DstPort == 65535 {
			log.Printf("last port scanned for %v dst port %s", s.dst, tcp.DstPort)
			return openPorts, nil
		}
		// if time.Since(start) > time.Second*20 {
		// 	log.Printf("timed out for %v aborting scan", s.dst)
		// 	return nil, nil
		// }

		eth := layers.Ethernet{}
		ip4 := layers.IPv4{}
		tcp := layers.TCP{}
		icmp := layers.ICMPv4{}

		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &tcp, &icmp)
		decodedLayers := make([]gopacket.LayerType, 0, 4)

		// Read in the next packet.
		data, _, err := handle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		} else if err != nil {
			log.Printf("error reading packet: %v", err)
			continue
		}
		// Parse the packet. Using DecodingLayerParser to be really fast
		if err := parser.DecodeLayers(data, &decodedLayers); err != nil {
			continue
		}
		for _, typ := range decodedLayers {
			switch typ {

			case layers.LayerTypeEthernet:
				continue
			case layers.LayerTypeIPv4:
				if ip4.NetworkFlow() != ipFlow {
					continue
				}
			case layers.LayerTypeTCP:
				if tcp.DstPort != tcpport {
					continue

				} else if tcp.RST {
					continue
				} else if tcp.SYN && tcp.ACK {
					openPorts[(tcp.SrcPort)] = "open"
					continue
				}
			case layers.LayerTypeICMPv4:

				switch icmp.TypeCode.Type() {
				case layers.ICMPv4TypeEchoReply:
					log.Printf("ICMP Echo Reply received from %v", ip4.SrcIP)
				case layers.ICMPv4TypeDestinationUnreachable:
					log.Printf(" port %v filtered", tcp.SrcPort)
				}
			}
		}
	}
}

// ConnScan performs a full handshake on each TCP port.
func (s *Scanner) ConnScan() (map[layers.TCPPort]string, error) {
	openPorts := make(map[layers.TCPPort]string)
	var mutex sync.Mutex

	retry := 3

	var wg sync.WaitGroup
	for port := 1; port <= 65535; port++ {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()

			// Use a loop for retries
			for attempt := 1; attempt <= retry; attempt++ {
				addr := fmt.Sprintf("[%s]:%d", s.dst.String(), p)
				conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
				if err == nil {
					conn.Close()
					serviceName, err := utils.GetServiceName(strconv.Itoa(p), "tcp")
					if err != nil {
						// Log or handle the error, and continue the loop
						log.Printf("Error getting service name for port %d: %v", p, err)
					}

					// Use mutex to safely update the map
					mutex.Lock()
					openPorts[layers.TCPPort(p)] = serviceName + " open"
					mutex.Unlock()

					break // Connection successful, exit the retry loop
				}

				// Sleep for a short duration before the next retry
				time.Sleep(500 * time.Millisecond)
			}
		}(port)
		if port == 65535 {
			log.Printf("last port scanned for %v dst port %d", s.dst, port)
			return openPorts, nil
		}

	}

	wg.Wait()

	return openPorts, nil
}
