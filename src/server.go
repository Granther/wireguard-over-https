package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/websocket"
)

// WebSocket upgrader
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all connections
	},
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Upgrade HTTP to WebSocket
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("WebSocket upgrade error:", err)
		return
	}
	defer conn.Close()

	log.Println("Client connected!")

	// Send a message to the client
	message := "Hello, WebSocket client!"
	err = conn.WriteMessage(websocket.TextMessage, []byte(message))
	if err != nil {
		log.Println("Write error:", err)
		return
	}

	// Keep listening for messages from the client
	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			log.Println("Read error:", err)
			break
		}
		fmt.Println("Received:", string(msg))
	}
}

func main() {
	http.HandleFunc("/ws", handleWebSocket)

	port := ":80"
	fmt.Println("WebSocket server listening on ws://localhost" + port + "/ws")
	log.Fatal(http.ListenAndServe(port, nil))
}
