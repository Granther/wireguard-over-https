package main

import (
	"fmt"
	"log"
	"net"

	"wireguard-go"
	//wg "github.com/libp2p/go-wireguard"
)

func main() {
	// Define the WireGuard interface configuration
	config := wg.InterfaceConfig{
		PrivateKey:  []byte("yC1Vh7EjsbYczHmN3NWRtHGzppAq8tbt/Ug2NrQTKEk="),
		//PresharedKey: []byte("7sXSTPuOGXNatgSLt3vXPILgiz+lnMNH4w/xBkFyNhU="),
	}

	// Create a WireGuard interface
	wgInterface, err := wg.NewInterface(config)
	if err != nil {
		log.Fatalf("Failed to create WireGuard interface: %v", err)
	}
	defer wgInterface.Close()

	fmt.Println("WireGuard interface created successfully!")

	// Define a peer
	peer := &wg.Peer{
		PublicKey: []byte("cV0fDSWyA/1f2nBKLo2dwyrFEeDjtXyIjlscLK1SCjo="),
		AllowedIPs: []*net.IPNet{
			{IP: net.IPv4(10, 0, 0, 1), Mask: net.CIDRMask(32, 32)},
		},
		Endpoint: &net.UDPAddr{
			IP:   net.ParseIP("192.168.1.41"),
			Port: 51820,
		},
		PersistentKeepaliveInterval: 25,
	}

	// Add the peer to the WireGuard interface
	err = wgInterface.AddPeer(peer)
	if err != nil {
		log.Fatalf("Failed to add peer: %v", err)
	}

	fmt.Println("Peer added successfully!")

	// Start the interface
	err = wgInterface.Run()
	if err != nil {
		log.Fatalf("Failed to run WireGuard interface: %v", err)
	}

	fmt.Println("WireGuard interface is running...")
	select {} // Keep the program running
}

