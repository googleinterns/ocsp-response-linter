// Package main provides the main command line functionality
package main

import (
	"crypto"
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/googleinterns/ocsp-response-linter/ocsptools"
	"io/ioutil"
	"net/http"
)

// createConn takes a provided server URL and attempts to establish a TLS connection with it
func createConn(serverURL string) (*tls.Conn, error) {
	config := &tls.Config{}

	tlsConn, err := tls.Dial("tcp", serverURL, config)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", serverURL, err)
	}

	return tlsConn, nil
}

// checkFromFile takes a path to an OCSP Response file and then reads, parses, and lints it
func checkFromFile(respFile string) error {
	ocspResp, err := ioutil.ReadFile(respFile)
	if err != nil {
		return fmt.Errorf("Error reading OCSP response file: %w", err)
	}
	// can't check signature w/o outside knowledge of who the issuer should be
	// TODO: add functionality so user can specify who the issuer is
	err = ocsptools.ParseAndLint(ocspResp, nil)
	if err != nil {
		return fmt.Errorf("Error parsing OCSP response: %w", err)
	}

	return nil
}

// checkFromCert takes a path to an ASN.1 DER encoded certificate file and constructs and sends an OCSP request
// then parses and lints the OCSP response
func checkFromCert(certFile string, isPost bool, ocspURL string, dir string, hash crypto.Hash) error {
	reqMethod := http.MethodGet
	if isPost {
		reqMethod = http.MethodPost
	}

	leafCert, err := ocsptools.ParseCertificateFile(certFile)
	if err != nil {
		return fmt.Errorf("Error parsing certificate from certificate file: %w", err)
	}

	issuerCert, err := ocsptools.GetIssuerCertFromLeafCert(leafCert)
	if err != nil {
		return fmt.Errorf("Error getting issuer certificate from certificate: %w", err)
	}

	ocspReq, err := ocsptools.CreateOCSPReq(ocspURL, leafCert, issuerCert, reqMethod, hash)
	if err != nil {
		return fmt.Errorf("Error creating OCSP Request: %w", err)
	}

	ocspResp, err := ocsptools.GetOCSPResponse(ocspReq)
	if err != nil {
		return fmt.Errorf("Error getting OCSP Response: %w", err)
	}

	return ocsptools.ParseAndLint(ocspResp, issuerCert)
}

// checkFromURL takes a server URL and constructs and sends an OCSP request to check that URL's certificate
// then parses and lints the OCSP response
func checkFromURL(serverURL string, shouldPrint bool, isPost bool, noStaple bool, ocspURL string, dir string, hash crypto.Hash) error {
	tlsConn, err := createConn(serverURL)
	if err != nil {
		return err
	}

	certChain := tlsConn.ConnectionState().PeerCertificates

	if len(certChain) == 0 {
		return fmt.Errorf("No certificate present for %s", serverURL)
	}

	// Is this right?
	if len(certChain) == 1 {
		return fmt.Errorf("Certificate for %s is a root certificate", serverURL)
	}

	leafCert := certChain[0] // the certificate we want to send to the CA
	issuerCert := certChain[1] // the certificate of the issuer of the leaf cert

	if shouldPrint {
		err = ocsptools.PrintCert(leafCert)
		if err != nil {
			return fmt.Errorf("Error printing certificate: %w", err)
		}
	}

	ocspResp := tlsConn.OCSPResponse()
	tlsConn.Close()

	if ocspResp == nil || noStaple {
		reqMethod := http.MethodGet
		if isPost {
			reqMethod = http.MethodPost
		}

		ocspReq, err := ocsptools.CreateOCSPReq(ocspURL, leafCert, issuerCert, reqMethod, hash)
		if err != nil {
			return fmt.Errorf("Error creating OCSP Request: %w", err)
		}

		ocspResp, err = ocsptools.GetOCSPResponse(ocspReq)
		if err != nil {
			return fmt.Errorf("Error getting OCSP Response: %w", err)
		}

		if dir != "" {
			err := ioutil.WriteFile(dir, ocspResp, 0644)
			if err != nil {
				return fmt.Errorf("Error writing OCSP Response to file %s: %w", dir, err)
			}
		}

		return ocsptools.ParseAndLint(ocspResp, issuerCert)
	} else {
		fmt.Println("Stapled OCSP Response")
		return ocsptools.ParseAndLint(ocspResp, issuerCert)
	}
}

// main parses the users commandline arguments & flags and then runs the appropriate functions
func main() {
	// TODO: extract flag descriptions into constants?
	inresp := flag.Bool("inresp", false, "Whether to read in an OCSP responses or not")
	incert := flag.Bool("incert", false, "Whether to read in certificate files or not")
	ocspurl := flag.String("ocspurl", "", "User provided OCSP url, default fetch from certificate")
	shouldPrint := flag.Bool("print", false, "Whether to print certificate or not") // may remove this print flag
	isPost := flag.Bool("post", false, "Whether to use POST for OCSP request")
	dir := flag.String("dir", "", "Where to write OCSP response, if blank don't write")
	noStaple := flag.Bool("nostaple", false, "Whether to send an OCSP request regardless of if there is a stapled OCSP response")	

	flag.Parse()

	if *inresp && *incert {
		panic("This tool can only parse one file format at a time. Please use only one of -inresp or -incert.")
	}

	if *inresp { // reading in OCSP response files
		respFiles := flag.Args()
		for _, respFile := range respFiles {
			err := checkFromFile(respFile)
			if err != nil {
				panic(fmt.Errorf("Error checking OCSP Response file %s: %w", respFile, err).Error())
			}
		}
	} else if *incert { // reading in certificate files
		certFiles := flag.Args()
		for _, certFile := range certFiles {
			err := checkFromCert(certFile, *isPost, *ocspurl, *dir, crypto.SHA1)
			if err != nil {
				panic(fmt.Errorf("Error checking certificate file %s: %w", certFile, err).Error())
			}
		}
	} else { // reading in server URLs
		serverURLs := flag.Args()

		for _, serverURL := range serverURLs {
			err := checkFromURL(serverURL, *shouldPrint, *isPost, *noStaple, *ocspurl, *dir, crypto.SHA256)
			if err == nil {
				return
			}
			fmt.Println("Validation failed for sending OCSP Request encoded with SHA256: " + err.Error())
			fmt.Println("Sending OCSP Request encoded with SHA1")
			err = checkFromURL(serverURL, *shouldPrint, *isPost, *noStaple, *ocspurl, *dir, crypto.SHA1)
			if err != nil {
				panic(fmt.Errorf("Error checking server URL %s: %w", serverURL, err).Error())
			}
		}
	}
}
