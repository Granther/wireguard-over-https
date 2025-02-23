package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"golang.org/x/net/tun"
)

const (
	tunName = "htun0" // Name of the TUN interface
	mtu     = 1500    // MTU size
)

func main() {
	// Create a TUN interface
	tunDev, err := tun.CreateTUN(tunName, mtu)
	if err != nil {
		log.Fatalf("Failed to create TUN device: %v", err)
	}
	defer tunDev.Close()

	fmt.Printf("TUN device %s created. Listening for packets...\n", tunName)

	// Get the TUN device file descriptor
	tunFd, err := tunDev.File()
	if err != nil {
		log.Fatalf("Failed to get TUN device file descriptor: %v", err)
	}

	// Configure the TUN interface (Run shell commands)
	setupTunInterface(tunName)

	// Read packets from the TUN interface
	packetBuf := make([]byte, mtu)
	for {
		n, err := tunFd.Read(packetBuf)
		if err != nil {
			log.Fatalf("Error reading from TUN device: %v", err)
		}

		fmt.Printf("Received %d bytes from %s\n", n, tunName)
		fmt.Printf("Packet Data: %x\n", packetBuf[:n]) // Print packet as hex
	}
}

// setupTunInterface sets up the TUN interface and routes traffic
func setupTunInterface(iface string) {
	// Set up IP address and bring up interface
	runCommand("ip", "addr", "add", "10.10.10.1/24", "dev", iface)
	runCommand("ip", "link", "set", iface, "up")

	// Redirect traffic from wg0 to htun0
	runCommand("iptables", "-t", "nat", "-A", "POSTROUTING", "-o", iface, "-j", "MASQUERADE")
	runCommand("iptables", "-A", "FORWARD", "-i", "wg0", "-o", iface, "-j", "ACCEPT")
	runCommand("iptables", "-A", "FORWARD", "-i", iface, "-o", "wg0", "-j", "ACCEPT")

	fmt.Println("TUN interface setup complete!")
}

// runCommand executes a system command
func runCommand(cmd string, args ...string) {
	if err := exec.Command(cmd, args...).Run(); err != nil {
		log.Fatalf("Command %s failed: %v", cmd, err)
	}
}

