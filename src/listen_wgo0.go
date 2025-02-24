package main

import (
	"fmt"

	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket"
)

func main() {
	if handle, err := pcap.OpenLive("wg0", 1600, true, pcap.BlockForever); err != nil {
	  panic(err)
	//} 
	//else if err := handle.SetBPFFilter("port "); err != nil { 
	  //panic(err)
	} else {
	  packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	  for packet := range packetSource.Packets() {
		fmt.Println("Recieved packet destined for peer, writing to WS")
		fmt.Println(packet)
		}
	}
}
