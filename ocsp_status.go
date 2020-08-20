// Package main provides the main command line functionality
package main

import (
	"./ocsptools"
	"crypto"
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
)

// createConn takes a provided server URL and attempts to establish a TLS connection with it
func createConn(severURL string) *tls.Conn {
	config := &tls.Config{}

	tlsConn, err := tls.Dial("tcp", severURL, config)
	if err != nil {
		panic("failed to connect: " + err.Error())
	}

	err = tlsConn.Handshake()
	if err != nil {
		panic("handshake failed: " + err.Error())
	}

	return tlsConn
}

func lintFile(respFile string) {
	ocspResp, err := ioutil.ReadFile(respFile)
	if err != nil {
		panic("Error reading OCSP response file: " + err.Error())
	}
	// can't check signature w/o outside knowledge of who the issuer should be
	// TODO: add functionality so user can specify who the issuer is
	err = ocsptools.ParseAndLint(ocspResp, nil)
	if err != nil {
		panic("Error parsing OCSP response: " + err.Error())
	}
}

func checkFromCert(certFile string, get bool, ocspURL string, dir string, hash crypto.Hash) error {
	reqMethod := http.MethodPost
	if get {
		reqMethod = http.MethodGet
	}

	ocspReq, issuerCert := ocsptools.CreateOCSPReqFromCert(certFile, ocspURL, reqMethod, hash)
	ocspResp := ocsptools.GetOCSPResponse(ocspReq, dir)

	return ocsptools.ParseAndLint(ocspResp, issuerCert)

}

func checkFromURL(serverURL string, print bool, get bool, ocspURL string, dir string, hash crypto.Hash) error {
	tlsConn := createConn(serverURL)

	certChain := tlsConn.ConnectionState().PeerCertificates
	rootCert := certChain[0]
	issuerCert := certChain[len(certChain)-1]

	if print {
		ocsptools.PrintCert(rootCert)
	}

	ocspResp := tlsConn.OCSPResponse()
	tlsConn.Close()

	if ocspResp == nil {
		fmt.Println("No OCSP response stapled")

		reqMethod := http.MethodPost
		if get {
			reqMethod = http.MethodGet
		}

		ocspReq := ocsptools.CreateOCSPReq(ocspURL, rootCert, issuerCert, reqMethod, hash)
		ocspResp = ocsptools.GetOCSPResponse(ocspReq, dir)

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
	print := flag.Bool("print", false, "Whether to print certificate or not") // may remove this print flag
	get := flag.Bool("get", false, "Whether to use GET for OCSP request")
	dir := flag.String("dir", "", "Where to write OCSP response, if blank don't write")	

	flag.Parse()

	if *inresp {
		respFiles := flag.Args()
		for _, respFile := range respFiles {
			lintFile(respFile)
		}
	} else if *incert {
		certFiles := flag.Args()
		for _, certFile := range certFiles {
			err := checkFromCert(certFile, *get, *ocspurl, *dir, crypto.SHA1)
			if err != nil {
				panic(err.Error())
			}
		}
	} else {
		serverURLs := flag.Args()

		for _, serverURL := range serverURLs {
			err := checkFromURL(serverURL, *print, *get, *ocspurl, *dir, crypto.SHA256)
			if err == nil {
				return
			}
			fmt.Println("Validation failed for sending OCSP Request encoded with SHA256: " + err.Error())
			err = checkFromURL(serverURL, *print, *get, *ocspurl, *dir, crypto.SHA1)
			if err != nil {
				panic(err.Error())
			}
		}
	}
}
