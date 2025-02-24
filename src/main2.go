package main

import (
	"fmt"
	"net"
	"net/http"

	"golang.org/x/net/websocket"
	gws "github.com/gorilla/websocket"

	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket"
)

const (
	LOCAL_WG_PORT = "52479"
	PEER_WG_PORT = "60885"
	WS_PORT = "8080"
	PEER_PUB_IP = "192.168.1.41"
	MY_PUB_IP = "127.0.0.1"
)

func main() {
	//clientRun()
	serverRun()
}

func serverRun() {
	awaitWSClient()
}

func clientRun() {
	// Connect to server websocket
	ws, err := connWebSock()
	if err != nil { panic(err) }

	go listenWS(ws) // Listen for incoming packets, these should be redirected to 52479 (local wireguard listen)
	// Listen and send

	// Catch traffic destined for 60885
	if handle, err := pcap.OpenLive("lo", 1600, true, pcap.BlockForever); err != nil {
	  panic(err)
	} else if err := handle.SetBPFFilter(fmt.Sprintf("port %s", PEER_WG_PORT)); err != nil { 
	  panic(err)
	} else {
	  packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	  for packet := range packetSource.Packets() {
		fmt.Println("Recieved packet destined for peer, writing to WS")
		ws.Write(packet.Data()) // Send packets over https
	  }
	}
}

func awaitWSClient() {
	fmt.Println("Awaiting client on websocket")

	var upgrader = gws.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true // Allow all connections
		},
	}
	
	handleWS := func (w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			fmt.Println("WebSocket upgrade error:", err)
			return
		}

		fmt.Println("Client connected")

		listenWSU(ws)
	}

	http.HandleFunc("/ws", handleWS)
	panic(http.ListenAndServe(fmt.Sprintf(":%s", WS_PORT), nil))
}

func listenWSU(ws *gws.Conn) {
	for {
		_, msg, err := ws.ReadMessage()
		if err != nil { fmt.Printf("Websocket read error: %v\n", err); continue }
		fmt.Println("Got message from peer on websocket, sending to wireguard...")

		err = sendToWG(msg)
		if err != nil { fmt.Printf("Unable to successfully send data to WG locally: %w\n", err); continue }
		fmt.Printf("Sent msg to local wireguard at localhost:%s\n", LOCAL_WG_PORT)
    	}
}

func listenWS(ws *websocket.Conn) {
	var msg = make([]byte, 512)
	for {
		n, err := ws.Read(msg)
		if err != nil { fmt.Println("Error reading from websocket"); continue }
		fmt.Println("Got message from peer on websocket, sending to wireguard...")

		err = sendToWG(msg[:n])
		if err != nil { fmt.Printf("Unable to successfully send data to WG locally: %w\n", err); continue }
		fmt.Printf("Sent msg to local wireguard at localhost:%s\n", LOCAL_WG_PORT)
	}
}

func sendToWG(data []byte) error {
	serverAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%s", LOCAL_WG_PORT))
	if err != nil { return fmt.Errorf("Unable to resolve udp addr for localhost:%s: %w", LOCAL_WG_PORT, err) }
	
	// Create udp conn
	conn, err := net.DialUDP("udp", nil,  serverAddr)
	if err != nil { return fmt.Errorf("Unable to dial WG when sending: %w", err) }
	defer conn.Close()

	_, err = conn.Write(data)
	if err != nil { return fmt.Errorf("Unable to write WG-destined data to udp conn: %w", err) }

	return nil
}

func connWebSock() (*websocket.Conn, error) {
	ws_url := fmt.Sprintf("ws://%s:%s/ws", PEER_PUB_IP, WS_PORT) 
	
	ws, err := websocket.Dial(ws_url, "", fmt.Sprintf("http://%s/", MY_PUB_IP))
	fmt.Printf("Dialing websocket at %s\n", ws_url)
	if err != nil {
		return nil, fmt.Errorf("WebSocket error: ", err)
	}
	return ws, nil
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
