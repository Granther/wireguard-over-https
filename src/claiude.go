package main

import (
    "fmt"
    "io"
    "log"
    "net"
    "time"
)

func handleConnection(conn net.Conn) {
    defer conn.Close()

    // Get connection details
    remoteAddr := conn.RemoteAddr().String()
    log.Printf("New connection from %s", remoteAddr)

    // Create a buffer for reading data
    buffer := make([]byte, 4096)
    
    // Set a read deadline to prevent hanging
    conn.SetReadDeadline(time.Now().Add(time.Hour))

    for {
        // Read incoming data
        n, err := conn.Read(buffer)
        if err != nil {
            if err != io.EOF {
                log.Printf("Error reading from %s: %v", remoteAddr, err)
            }
            return
        }

        // Log the received data
        log.Printf("Received %d bytes from %s: %s", n, remoteAddr, string(buffer[:n]))
        
        // You can also write back to the connection if needed:
        // conn.Write([]byte("Received your message\n"))
    }
}

func main() {
    // Create listener
    listener, err := net.Listen("tcp", "127.0.0.1:60885")
    if err != nil {
        log.Fatalf("Failed to create listener: %v", err)
    }
    defer listener.Close()

    fmt.Printf("Listening on %s\n", listener.Addr())

    // Accept connections
    for {
        conn, err := listener.Accept()
        if err != nil {
            log.Printf("Failed to accept connection: %v", err)
            continue
        }

        // Handle each connection in a goroutine
        go handleConnection(conn)
    }
}
