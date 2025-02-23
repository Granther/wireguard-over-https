package main

import (
	"fmt"
	
	"golang.org/x/net/websocket"

	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket"
)

func main() {
	ws := webSock()
	//err := textSocket(ws); err != nil {
	//	panic(err)	
	//}

	go listenWS(ws)

	if handle, err := pcap.OpenLive("lo", 1600, true, pcap.BlockForever); err != nil {
	  panic(err)
	} else if err := handle.SetBPFFilter("port 60885"); err != nil {  // optional
	  panic(err)
	} else {
	  packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	  for packet := range packetSource.Packets() {
		fmt.Println("packet: ", packet)
		ws.Write(packet.Data())
	  }
	}
}

func listenWS(ws *websocket.Conn) {
	var msg = make([]byte, 512)
	for {
		_, err := ws.Read(msg)
		if err != nil { fmt.Println("Error reading from websocket"); continue }
		fmt.Println("Got message from server on websocket")
	}
}

func webSock() *websocket.Conn {
	ws, err := websocket.Dial("ws://192.168.1.41:8080/ws", "", "http://192.168.1.68/")
	fmt.Println("Dialing websocker")
	//ws, err := websocket.Dial("ws://localhost:8080/ws", "", "http://localhost/")
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
	fmt.Println("Read message: ", string(msg[:n]))
	return nil
}
