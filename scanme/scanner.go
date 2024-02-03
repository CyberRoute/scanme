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
	tcpsequencer *TCPSequencer
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
		buf:          gopacket.NewSerializeBuffer(),
		tcpsequencer: NewTCPSequencer(),
	}

	iface, gw, src, err := router.Route(ip)
	if err != nil {
		return nil, err
	}

	// If scanning localhost, set the interface to loopback
	if ip.Equal(src) {
		iface, err = net.InterfaceByName("lo")
		if err != nil {
			return nil, fmt.Errorf("error getting loopback interface: %v", err)
		}
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
	var err error
	retries := 10

	for retries > 0 {
		err = s.handle.WritePacketData(s.buf.Bytes())
		if err == nil {
			break // Successfully sent, exit the loop
		}

		retries--
		// introduce a small delay to allow the network interface to flush the queue
		time.Sleep(10 * time.Millisecond)
	}
	return err
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
		parser.IgnoreUnsupported = true
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

// HandlePacket processes a packet, extracting and analyzing its layers to determine
// if it corresponds to a SYN-ACK response for a given TCP port. If a SYN-ACK is
// detected, it updates the provided openPorts map to mark the corresponding port as "open".
//
// Parameters:
//   - data: The raw packet data to be processed.
//   - srcport: The source port to match in the TCP layer.
//   - openPorts: A map storing open ports and their status.
//
// The function uses the gopacket library to decode the packet layers, filtering
// based on Ethernet, IPv4, TCP, and ICMPv4 layers. If a SYN-ACK is detected on the
// specified source port, it updates the openPorts map accordingly.
func (s *Scanner) HandlePacket(data []byte, srcport layers.TCPPort, openPorts map[layers.TCPPort]string) {
	var eth layers.Ethernet
	var ip4 layers.IPv4
	var tcp layers.TCP
	var icmp layers.ICMPv4
	var payload gopacket.Payload
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &tcp, &icmp, &payload)
	parser.IgnoreUnsupported = true
	decoded := []gopacket.LayerType{}

	err := parser.DecodeLayers(data, &decoded)
	if err != nil {
		log.Printf("Decoding error:%v\n", err)
	}
	ipFlow := gopacket.NewFlow(layers.EndpointIPv4, s.dst, s.src)

	for _, typ := range decoded {
		switch typ {

		case layers.LayerTypeEthernet:
			continue
		case layers.LayerTypeIPv4:
			if ip4.NetworkFlow() != ipFlow {
				continue
			}
		case layers.LayerTypeTCP:
			if tcp.DstPort != srcport {
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

// Synscan performs a SYN port scan on the specified destination IP address using the provided network interface.
// It sends SYN packets to ports [1, 65535] and records open ports in a map. The function employs ARP requests,
// ICMP Echo Requests, and packet capturing to identify open, closed, or filtered ports.
// The function returns a map of open ports along with their status or an error if any occurs during the scan.
func (s *Scanner) Synscan() (map[layers.TCPPort]string, error) {
	openPorts := make(map[layers.TCPPort]string)

	var srcMAC, dstMAC net.HardwareAddr

	// Check if the destination IP is 127.0.0.1 or source and destination are the same
	if s.dst.Equal(net.IPv4(127, 0, 0, 1)) || s.src.Equal(s.dst) {
		// Use loopback MAC address for both source and destination
		// srcMAC = net.HardwareAddr{0, 0, 0, 0, 0, 0}
		// dstMAC = net.HardwareAddr{0, 0, 0, 0, 0, 0}
		log.Fatal("You are trying to scan local address which require an open socket")
	} else {
		// Obtain MAC address from ARP request
		mac, err := s.sendARPRequest()
		if err != nil {
			return nil, err
		}
		srcMAC = s.iface.HardwareAddr
		dstMAC = mac
	}

	srctcpport, err := getFreeTCPPort()
	if err != nil {
		return nil, err
	}

	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := layers.IPv4{
		SrcIP:    s.src,
		DstIP:    s.dst,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcpOption := layers.TCPOption{
		OptionType:   layers.TCPOptionKindMSS,
		OptionLength: 4,
		OptionData:   []byte{0x05, 0xB4},
	}

	tcp := layers.TCP{
		SrcPort: layers.TCPPort(srctcpport),
		DstPort: 0,
		Window:  1024,
		Options: []layers.TCPOption{tcpOption},
		Seq:     s.tcpsequencer.Next(),
		SYN:     true,
	}

	err = tcp.SetNetworkLayerForChecksum(&ip4)
	if err != nil {
		return nil, err
	}
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

		// Read in the next packet.
		data, _, err := handle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		} else if err != nil {
			log.Printf("error reading packet: %v", err)
			continue
		}

		// Handle the packet and update openPorts map
		s.HandlePacket(data, srctcpport, openPorts)
	}
}

// ConnScan performs a full handshake on each TCP port, it supports ipv4 and ipv6.
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

func (s *Scanner) HandlePacketSock(data []byte, srcport layers.TCPPort) {
	var ip4 layers.IPv4
	var tcp layers.TCP
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeTCP, &ip4, &tcp)
	parser.IgnoreUnsupported = true
	decoded := []gopacket.LayerType{}

	err := parser.DecodeLayers(data, &decoded)
	if err != nil {
		log.Printf("Decoding error:%v\n", err)
	}
	for _, typ := range decoded {
		switch typ {
		case layers.LayerTypeTCP:
			if tcp.DstPort == layers.TCPPort(srcport) {
				if tcp.SYN && tcp.ACK {
					log.Printf("Port %v is OPEN\n", tcp.SrcPort)
				}
			}
		}
	}
}

func (s *Scanner) SendSynTCP4(ip string, p layers.TCPPort) {

	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		fmt.Println(err)
	}
	defer conn.Close()

	srctcpport, err := getFreeTCPPort()
	if err != nil {
		fmt.Println(err)
	}

	ip4 := layers.IPv4{
		SrcIP:    s.src,
		DstIP:    s.dst,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}

	tcpOption := layers.TCPOption{
		OptionType:   layers.TCPOptionKindMSS,
		OptionLength: 4,
		OptionData:   []byte{0x05, 0xB4},
	}

	tcp := layers.TCP{
		SrcPort: layers.TCPPort(srctcpport),
		DstPort: p,
		Window:  1024,
		Options: []layers.TCPOption{tcpOption},
		Seq:     s.tcpsequencer.Next(),
		SYN:     true,
	}

	err = tcp.SetNetworkLayerForChecksum(&ip4)
	if err != nil {
		fmt.Println(err)
	}

	err = s.sendsock(ip, conn, &tcp)
	if err != nil {
		fmt.Println(err)
	}

	// Set deadline so we don't wait forever.
	if err := conn.SetDeadline(time.Now().Add(40 * time.Millisecond)); err != nil {
		fmt.Println(err)
	}

	for {
		b := make([]byte, 4096)
		n, addr, err := conn.ReadFrom(b)
		if err != nil {
			break
		} else if addr.String() == net.ParseIP(ip).String() {
			// Decode a packet
			s.HandlePacketSock(b[:n], srctcpport)
		}
	}
}

func (s *Scanner) SendSynTCP6(ip string, p layers.TCPPort) {

	conn, err := net.ListenPacket("ip6:tcp", "::")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer conn.Close()

	srctcpport, err := getFreeTCPPort()
	if err != nil {
		fmt.Println(err)
	}
	ip6 := layers.IPv6{
		DstIP:      s.dst,
		SrcIP:      s.src,
		Version:    6,
		HopLimit:   255,
		NextHeader: layers.IPProtocolTCP,
	}

	tcpOption := layers.TCPOption{
		OptionType:   layers.TCPOptionKindMSS,
		OptionLength: 4,
		OptionData:   []byte{0x05, 0xB4},
	}

	tcp := layers.TCP{
		SrcPort: layers.TCPPort(srctcpport),
		DstPort: p,
		Window:  1024,
		Options: []layers.TCPOption{tcpOption},
		Seq:     s.tcpsequencer.Next(),
		SYN:     true,
	}

	err = tcp.SetNetworkLayerForChecksum(&ip6)
	if err != nil {
		fmt.Println(err)
	}

	err = s.sendsock(ip, conn, &tcp)
	if err != nil {
		fmt.Println(err)
	}
	// Set deadline so we don't wait forever.
	if err := conn.SetDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		log.Fatal(err)
	}
	for {
		b := make([]byte, 4096)
		n, addr, err := conn.ReadFrom(b)
		if err != nil {
			break
		} else if addr.String() == net.ParseIP(ip).String() {
			// Decode a packet
			packet := gopacket.NewPacket(b[:n], layers.LayerTypeTCP, gopacket.Default)
			// Get the TCP layer from this packet
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp, ok := tcpLayer.(*layers.TCP)
				if !ok {
					continue
				}
				if tcp.DstPort == layers.TCPPort(srctcpport) {
					if tcp.SYN && tcp.ACK {
						log.Printf("Port %v is OPEN\n", tcp.SrcPort)
					} else {
						// Port is closed
						log.Printf("Port %v CLOSED", tcp.SrcPort)
					}
					return
				}
			}
		}
	}
}

func (s *Scanner) sendsock(destIP string, conn net.PacketConn, l ...gopacket.SerializableLayer) error {
	buf := gopacket.NewSerializeBuffer()

	if err := gopacket.SerializeLayers(buf, s.opts, l...); err != nil {
		return err
	}

	retries := 10

	for retries > 0 {
		_, err := conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: net.ParseIP(destIP)})
		if err == nil {
			break // Successfully sent, exit the loop
		}

		retries--
		// introduce a small delay to allow the network interface to flush the queue
		time.Sleep(10 * time.Millisecond)
	}

	return nil
}
