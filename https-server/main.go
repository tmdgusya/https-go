package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
)

// loadCertificate loads a TLS certificate and private key from the specified files.
// It returns the loaded certificate or fatally exits if loading fails.
func loadCertificate(certFile, keyFile string) tls.Certificate {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("failed to load server certificate and key: %v", err)
	}
	return cert
}

func main() {
	cert := loadCertificate("cert.pem", "key.pem")

	// set up a TLS config with the loaded certificate
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	listener, err := tls.Listen("tcp", ":8443", tlsConfig)
	if err != nil {
		log.Fatalf("failed to listen on port 8443: %v", err)
	}
	defer listener.Close()

	log.Println("listening on port 8443")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("failed to accept connection: %v", err)
			continue
		}

		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	log.Printf("connection from %s", conn.RemoteAddr())

	// Create a buffered reader for more efficient reading
	reader := bufio.NewReader(conn)

	tlsConn := conn.(*tls.Conn)

	// Get connection state
	state := tlsConn.ConnectionState()
	log.Printf("TLS Version: %x", state.Version)
	log.Printf("Cipher Suite: %x", state.CipherSuite)
	log.Printf("Session Reused: %v", state.DidResume)

	for {
		// Read until newline or max buffer size
		message, err := reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				log.Printf("failed to read from connection: %v", err)
			}
			return
		}

		message = strings.TrimSpace(message)
		log.Printf("received from %s: %q", conn.RemoteAddr(), message)

		// Send response with newline for proper framing
		response := fmt.Sprintf("Server received: %s\n", message)
		if _, err := conn.Write([]byte(response)); err != nil {
			log.Printf("failed to write to connection: %v", err)
			return
		}
	}
}
