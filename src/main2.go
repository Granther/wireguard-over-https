package main

import (
	"fmt"
	
	"golang.org/x/net/websocket"

	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket"
)

func main() {
	if err := textSocket(webSock()); err != nil {
		panic(err)	
	}

	if handle, err := pcap.OpenLive("lo", 1600, true, pcap.BlockForever); err != nil {
	  panic(err)
	} else if err := handle.SetBPFFilter("port 60885"); err != nil {  // optional
	  panic(err)
	} else {
	  packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	  for packet := range packetSource.Packets() {
		fmt.Println("packet: ", packet)
	  }
	}
}

func webSock() *websocket.Conn {
	//ws, err := websocket.Dial("wss://192.168.1.41/wg", "", "http://192.168.1.68/")
	fmt.Println("Dialing websocker")
	ws, err := websocket.Dial("wss://localhost:80/wg", "", "http://localhost/")
	if err != nil {
		fmt.Println("WebSocket error:", err)
		return nil
	}
	return ws
}

func textSocket(ws *websocket.Conn) error {
	if _, err := ws.Write([]byte("hello")); err != nil {
		return err 
	}
	fmt.Println("Sent")

	var msg = make([]byte, 512)
	var n int
	var err error
	if n, err = ws.Read(msg); err != nil {
		return err
	}
	fmt.Println("Read message: ", msg[:n])
	return nil
}
