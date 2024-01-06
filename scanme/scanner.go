package scanme

import (
	"fmt"
	"log"
	"net"
	//"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/routing"

)

// scanner handles scanning a single IP address.
type scanner struct {
	// iface is the interface to send packets on.
	iface *net.Interface
	// destination, gateway (if applicable), and source IP addresses to use.
	dst, gw, src net.IP

	handle *pcap.Handle

	// opts and buf allow us to easily serialize packets in the send()
	// method.
	opts gopacket.SerializeOptions
	buf  gopacket.SerializeBuffer
}

// newScanner creates a new scanner for a given destination IP address, using
// router to determine how to route packets to that IP.
func NewScanner(ip net.IP, router routing.Router) (*scanner, error) {
	s := &scanner{
		dst: ip,
		opts: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		buf: gopacket.NewSerializeBuffer(),
	}

	iface, gw, src, _ := router.Route(ip)
	log.Printf("scanning ip %v with interface %v, gateway %v, src %v", ip, iface.Name, gw, src)
	s.gw, s.src, s.iface = gw, src, iface

	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("error opening pcap handle: %v", err)
	}
	s.handle = handle

	return s, nil
}

// Closes the pcap handle
func (s *scanner) Close() {
	if s.handle != nil {
		s.handle.Close()
	}
}

func (s *scanner) sendARPRequest() (net.HardwareAddr, error) {
	arpDst := s.dst
	if s.gw != nil {
		arpDst = s.gw
	}
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
	bpf := "arp"
	if err := s.handle.SetBPFFilter(bpf); err != nil {
		log.Fatalln(err)
	}
	// Send a single ARP request packet (we never retry a send, since this
	// SerializeLayers clears the given write buffer, then writes all layers
	// into it so they correctly wrap each other. Note that by clearing the buffer,
	// it invalidates all slices previously returned by w.Bytes()
	gopacket.SerializeLayers(s.buf, s.opts, &eth, &arp)

	s.handle.WritePacketData(s.buf.Bytes()) // WritePacketData calls pcap_sendpacket, injecting the given data into the pcap handle

	for {
		data, _, err := s.handle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		} else if err != nil {
			return net.HardwareAddr{}, err
		}

		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &arp)
		decoded := []gopacket.LayerType{}
		if err := parser.DecodeLayers(data, &decoded); err != nil {
			return net.HardwareAddr{}, err
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

func (s *scanner) Synscan() error {
	mac, err := s.sendARPRequest()
	if err != nil {
		return err
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
		SrcPort: 54321,
		DstPort: 0, // will be incremented during the scan
		SYN:     true,
	}

	tcp.SetNetworkLayerForChecksum(&ip4)
	//start := time.Now()

	ipFlow := gopacket.NewFlow(layers.EndpointIPv4, s.dst, s.src)
	bpf := fmt.Sprintf("tcp dst port %d", tcp.SrcPort)

	if err := s.handle.SetBPFFilter(bpf); err != nil {
		log.Fatalln(err)
	}


	for {
		// Send one packet per loop iteration until we've sent packets
		// to all of ports [1, 65535].

		if tcp.DstPort < 65535 {
			tcp.DstPort++
			gopacket.SerializeLayers(s.buf, s.opts, &eth, &ip4, &tcp)
			s.handle.WritePacketData(s.buf.Bytes())
		}
		
		// Time out 5 seconds after the last packet we sent.
		// if time.Since(start) > time.Second*5 {
		// 	log.Printf("timed out for %v, assuming we've seen all we can", s.dst)
		// }
		eth := &layers.Ethernet{}
		ip4 := &layers.IPv4{}
		tcp := &layers.TCP{}
		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, eth, ip4, tcp)
		decodedLayers := make([]gopacket.LayerType, 0, 4)

		// Read in the next packet.
		data, _, err := s.handle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		} else if err != nil {
			log.Printf("error reading packet: %v", err)
			continue
		}
		// Parse the packet. Using DecodingLayerParser to be really fast
		if err := parser.DecodeLayers(data, &decodedLayers); err != nil {
			fmt.Println("Error", err)
		}
		for _, typ := range decodedLayers {
			switch typ {
			case layers.LayerTypeARP:
				continue
			case layers.LayerTypeEthernet:
				//fmt.Println("    Eth ", eth.SrcMAC, eth.DstMAC)
				continue
			case layers.LayerTypeIPv4:
				//fmt.Println("    IP4 ", ip41.SrcIP, ip41.DstIP)
				if ip4.NetworkFlow() != ipFlow {
					continue
				}
				continue
			case layers.LayerTypeTCP:
				//fmt.Println("    TCP ", tcp1.SrcPort, tcp1.DstPort)
				if tcp.DstPort != 54321 {
					continue
				} else if tcp.SYN && tcp.ACK {
					log.Printf("  port %v open", tcp.SrcPort)
					continue
				} else if tcp.RST {
					log.Printf("  port %v closed", tcp.SrcPort)
					continue
				}
			}
		}
	}
}
