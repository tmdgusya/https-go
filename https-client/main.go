package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"strings"
)

func loadRootCA(certFile string) *x509.CertPool {
	// Create a certificate pool for trusted certificates
	caCert, err := os.ReadFile(certFile)
	if err != nil {
		log.Fatalf("failed to read CA certificate: %v", err)
	}

	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(caCert); !ok {
		log.Fatal("failed to append CA certificate")
	}

	return certPool
}

func main() {
	// Load the self-signed certificate
	certPool := loadRootCA("../https-server/cert.pem")

	// Configure TLS client
	tlsConfig := &tls.Config{
		RootCAs:            certPool,
		InsecureSkipVerify: false, // Set to true if you want to skip certificate verification (not recommended for production)
		MinVersion:         tls.VersionTLS12,
		KeyLogWriter:       os.Stdout, // WARNING: Only use for debugging!
	}

	// Create a TLS connection
	conn, err := tls.Dial("tcp", "localhost:8443", tlsConfig)
	if err != nil {
		log.Fatalf("failed to connect: %v", err)
	}
	defer conn.Close()

	log.Printf("connected to %s", conn.RemoteAddr())

	// Get connection state information
	state := conn.ConnectionState()
	fmt.Printf("TLS Version: %x\n", state.Version)
	fmt.Printf("Cipher Suite: %x\n", state.CipherSuite)
	fmt.Printf("Server Name: %s\n", state.ServerName)

	// Use bufio for better reading
	reader := bufio.NewReader(os.Stdin)
	connReader := bufio.NewReader(conn)

	// Interactive loop
	for {
		fmt.Print("Enter message (or 'quit' to exit): ")
		message, err := reader.ReadString('\n')
		if err != nil {
			log.Printf("failed to read input: %v", err)
			break
		}

		message = strings.TrimSpace(message)
		if message == "quit" {
			break
		}

		// Add newline for message framing
		message += "\n"
		if _, err := conn.Write([]byte(message)); err != nil {
			log.Printf("failed to write to connection: %v", err)
			break
		}

		// Read response
		response, err := connReader.ReadString('\n')
		if err != nil {
			log.Printf("failed to read from connection: %v", err)
			break
		}

		fmt.Printf("Server response: %q\n", strings.TrimSpace(response))
	}
}
