package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	// Get the source IP - this should be your local tunnel IP on the WireGuard interface
	// You may need to change this to your actual WireGuard IP
	srcIP := net.ParseIP("127.0.0.1") // Your WireGuard IP
	dstIP := net.ParseIP("10.0.0.1") // Target WireGuard IP

	// Create a new ICMP echo request packet
	packet, err := createPingPacket(srcIP, dstIP)
	if err != nil {
		log.Fatalf("Failed to create ping packet: %v", err)
	}

	// Print the packet for debugging
	fmt.Println("Created ICMP Echo Request packet:")
	fmt.Printf("  Source IP: %s\n", srcIP)
	fmt.Printf("  Dest IP: %s\n", dstIP)

	// Inject the packet onto the WireGuard interface
	err = injectPacket("wg0", packet)
	if err != nil {
		log.Fatalf("Failed to inject packet: %v", err)
	}
	fmt.Println("Packet injected successfully")

	// Wait a bit for the ping to go through
	time.Sleep(time.Second)

	// Optionally, listen for the ping reply
	go listenForPingReply("wg0", dstIP, srcIP)

	// Keep the program running to see the reply
	time.Sleep(5 * time.Second)
}

func createPingPacket(srcIP, dstIP net.IP) ([]byte, error) {
	// Initialize IPv4 layer
	ipLayer := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolICMPv4,
		SrcIP:    srcIP,
		DstIP:    dstIP,
		IHL:      5,
	}

	// Initialize ICMP layer (Echo Request)
	icmpLayer := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		Id:       1234, // ID for tracking the request/reply
		Seq:      1,    // Sequence number
	}

	// Payload for the ICMP packet
	payload := []byte("WIREPACKETTEST")

	// Create serialization buffer
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	// Serialize all layers
	err := gopacket.SerializeLayers(buf, opts,
		ipLayer,
		icmpLayer,
		gopacket.Payload(payload),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize packet: %w", err)
	}

	return buf.Bytes(), nil
}

func injectPacket(interfaceName string, packetData []byte) error {
	// Open device for packet injection
	handle, err := pcap.OpenLive(interfaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open interface %s: %w", interfaceName, err)
	}
	defer handle.Close()

	// Inject the packet
	if err := handle.WritePacketData(packetData); err != nil {
		return fmt.Errorf("failed to inject packet: %w", err)
	}

	return nil
}

func listenForPingReply(interfaceName string, srcIP, dstIP net.IP) {
	// Set up pcap to listen for reply
	handle, err := pcap.OpenLive(interfaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Printf("Failed to open interface for listening: %v", err)
		return
	}
	defer handle.Close()

	// Set BPF filter for ICMP echo reply from the target
	filter := fmt.Sprintf("icmp and src host %s and dst host %s", srcIP.String(), dstIP.String())
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Printf("Failed to set BPF filter: %v", err)
		return
	}

	fmt.Printf("Listening for ping reply on %s\n", interfaceName)
	
	// Start packet processing loop
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Look for ICMP layer
		if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
			icmp, _ := icmpLayer.(*layers.ICMPv4)
			
			// Check if it's an echo reply
			if icmp.TypeCode.Type() == layers.ICMPv4TypeEchoReply {
				fmt.Println("Received ping reply!")
				fmt.Printf("  ICMP ID: %d, Sequence: %d\n", icmp.Id, icmp.Seq)
				if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
					ip, _ := ipLayer.(*layers.IPv4)
					fmt.Printf("  From: %s, To: %s\n", ip.SrcIP, ip.DstIP)
				}
				return
			}
		}
	}
}
