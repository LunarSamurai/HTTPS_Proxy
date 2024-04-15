package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	pkix509 "crypto/x509/pkix"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
)

// Blocked URLs
var blockedURLs = map[string]bool{
	"www.example.com": true, // Add more URLs here
}

// Logging Middleware
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Received request for %s from %s", r.URL, r.RemoteAddr)
		next.ServeHTTP(w, r) // Call the next handler
		log.Printf("Processed request for %s", r.URL)
	})
}

func handleRequestAndRedirect(res http.ResponseWriter, req *http.Request) {
	destinationUrl := req.URL.Scheme + "://" + req.URL.Host + req.URL.Path
	if req.URL.RawQuery != "" {
		destinationUrl += "?" + req.URL.RawQuery
	}

	// Block URLs
	if _, found := blockedURLs[req.URL.Host]; found {
		http.Error(res, "Blocked URL", http.StatusForbidden)
		return
	}

	// Create a new request
	proxyReq, err := http.NewRequest(req.Method, destinationUrl, req.Body)
	if err != nil {
		log.Printf("Error in forwarding request: %v\n", err)
		http.Error(res, "Error in creating proxy request", http.StatusInternalServerError)
		return
	}

	// Copy headers
	for header, values := range req.Header {
		for _, value := range values {
			proxyReq.Header.Add(header, value)
		}
	}

	// Modify headers (example: adding a custom header)
	proxyReq.Header.Add("X-Proxy-Header", "MyProxy")

	client := &http.Client{}
	resp, err := client.Do(proxyReq)
	if err != nil {
		http.Error(res, "Error in forwarding request", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Copy response headers and status code
	for header, values := range resp.Header {
		for _, value := range values {
			res.Header().Add(header, value)
		}
	}
	res.WriteHeader(resp.StatusCode)

	// Copy the response body
	io.Copy(res, resp.Body)
}

func handleHTTPSConnect(w http.ResponseWriter, r *http.Request) {
	// Hijack the connection
	hijacker, ok := w.(http.Hijacker)

	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "Error hijacking connection", http.StatusInternalServerError)
		return
	}

	// Generate certificate for domain
	cert, err := generateCertificate(r.Host)
	if err != nil {
		log.Printf("Error generating certificate: %v", err)
		clientConn.Close()
		return
	}

	// Create a TLS config with the generated certificate
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		// InsecureSkipVerify: true, // Use this ONLY for testing with self-signed certs
	}

	// Establish a TLS connection with the client
	tlsConn := tls.Server(clientConn, tlsConfig)
	err = tlsConn.Handshake()

	if err != nil {
		log.Printf("TLS handshake error: %v", err)
		tlsConn.Close()
		return
	}

	clientRequest, err := http.ReadRequest(bufio.NewReader(tlsConn))
	if err != nil {
		log.Printf("Error reading request from client: %v", err)
		return
	}

	// Step 2: Send the request to the destination server
	destinationConn, err := net.Dial("tcp", clientRequest.URL.Host)
	if err != nil {
		log.Printf("Error connecting to destination: %v", err)
		return
	}

	// Assume the destination server uses HTTP for simplicity
	clientRequest.Write(destinationConn)

	// Step 3: Receive the response from the server
	serverResponse, err := http.ReadResponse(bufio.NewReader(destinationConn), clientRequest)
	if err != nil {
		log.Printf("Error reading response from server: %v", err)
		return
	}

	// Step 4: Send the response back to the client
	serverResponse.Write(tlsConn)
}

func generateCertificateForDomain(s string) {
	panic("unimplemented")
}

func generateCertificate(domain string) (tls.Certificate, error) {

	// Create a new key-pair
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	// Generate a CSR from the private key
	csr, _ := pkix509.CertificateAuthority(rand.Reader, &pkix509.CertificateAuthority{}, privKey)

	// Use the CSR to generate a cert signed by your CA
	// Fix: Declare the ca variable
	var ca *pkix509.CertificateAuthority

	cert, _ := ca.Sign(csr)

	// Return signed certificate and private key
	return tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  privKey,
	}, nil
}

func main() {

	fmt.Println("Proxy server is running on port 8080")
	fmt.Println("HTTP or HTTPS? (H or HS):")

	var MenuAnswer string
	fmt.Scanln(&MenuAnswer)

	if MenuAnswer == "H" {
		http.Handle("/", loggingMiddleware(http.HandlerFunc(handleRequestAndRedirect)))
		log.Fatal(http.ListenAndServe(":8080", nil))
	} else if MenuAnswer == "HS" {
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				handleHTTPSConnect(w, r)
			} else {
				// Handle HTTP requests normally
				handleRequestAndRedirect(w, r)
			}
		})
		log.Fatal(http.ListenAndServeTLS(":8080", "path/to/cert.pem", "path/to/key.pem", nil))
	} else {
		fmt.Println("Entered Wrong Response, please try again; ending...")
	}

}
