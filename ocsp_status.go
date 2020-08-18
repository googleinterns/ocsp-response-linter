// Package main provides the main command line functionality
package main

import (
	"./linter"
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"fmt"
	"github.com/grantae/certinfo"
	"golang.org/x/crypto/ocsp"
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

// printCert prints the givern certificate using the external library github.com/grantae/certinfo
func printCert(cert *x509.Certificate) {
	result, err := certinfo.CertificateText(cert)
	if err != nil {
		panic(err.Error())
	}
	fmt.Print(result)
}

// TODO: function that prints out an OCSP response
func printResp(resp *ocsp.Response) {

}

// createOCSPReq creates an OCSP request using either GET or POST (see IETF RFC 6960)
// rootCert is the root certificate (first certificate in the chain)
// issuerCert is the last certificate in the chain
// reqType is either GET or POST (TODO: change reqType to not be string)
func createOCSPReq(rootCert *x509.Certificate, issuerCert *x509.Certificate, reqType string) *http.Request {
	// not sure what to do if there are multiple here
	// make a request for each?
	ocspURL := rootCert.OCSPServer[0]

	// TODO: Look into Request Options
	ocspReq, err := ocsp.CreateRequest(rootCert, issuerCert, &ocsp.RequestOptions{
		Hash: crypto.SHA1,
	})
	if err != nil {
		panic(err.Error())
	}

	body := bytes.NewBuffer(ocspReq)

	if reqType == http.MethodGet {
		// Do I need to worry about line breaks?
		enc := base64.StdEncoding.EncodeToString(ocspReq)
		ocspURL += "/" + enc
		body = bytes.NewBuffer(nil) // body = nil runs into errors
	}

	httpReq, err := http.NewRequest(reqType, ocspURL, body)
	if err != nil {
		panic(err.Error())
	}

	httpReq.Header.Add("Content-Type", "application/ocsp-request")
	httpReq.Header.Add("Accept", "application/ocsp-response")

	return httpReq
}

// getOCSPResponse constructs and sends an OCSP request then returns the OCSP response
func getOCSPResponse(rootCert *x509.Certificate, issuerCert *x509.Certificate, reqType string, dir string) *ocsp.Response {
	httpReq := createOCSPReq(rootCert, issuerCert, reqType)

	httpClient := &http.Client{}
	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		panic(err.Error())
	}

	defer httpResp.Body.Close()
	ocspResp, err := ioutil.ReadAll(httpResp.Body)
	if err != nil {
		// if HTTP 405 results from GET request, need to say that's a lint
		panic(err.Error())
	}

	if dir != "" {
		err := ioutil.WriteFile(dir, ocspResp, 0644)
		if err != nil {
			panic("Error writing to file: " + err.Error())
		}
	}

	parsedResp, err := ocsp.ParseResponse(ocspResp, issuerCert)
	if err != nil {
		fmt.Println(string(ocspResp))
		panic(err.Error())
	}

	return parsedResp
}

// main parses the users commandline arguments & flags and then runs the appropriate functions
func main() {
	// TODO: extract flag descriptions into constants?
	print := flag.Bool("print", false, "Whether to print certificate or not")
	dir := flag.String("dir", "", "Where to write OCSP response, if blank don't write")
	reqType := flag.String("type", http.MethodPost, "Whether to use GET or POST for OCSP request")
	in := flag.Bool("in", false, "Whether to read in an OCSP Response or not")

	flag.Parse()

	if *in {
		respFiles := flag.Args()

		for _, respFile := range respFiles {
			ocspResp, err := ioutil.ReadFile(respFile)
			if err != nil {
				panic("Error reading file: " + err.Error())
			}
			// can't check signature w/o outside knowledge of who the issuer should be
			// TODO: add functionality so user can specify who the issuer is
			parsedResp, err := ocsp.ParseResponse(ocspResp, nil)
			if err != nil {
				fmt.Println(string(ocspResp))
				panic(err.Error())
			}
			linter.CheckOCSPResp(parsedResp)
		}
	} else {
		certURLs := flag.Args()

		for _, certURL := range certURLs {
			tlsConn := createConn(certURL)

			// TODO: Print certificates to directory
			certChain := tlsConn.ConnectionState().PeerCertificates
			rootCert := certChain[0]
			issuerCert := certChain[len(certChain)-1]

			if *print {
				printCert(rootCert)
			}

			ocspResp := tlsConn.OCSPResponse()

			if ocspResp == nil {
				fmt.Println("No OCSP response stapled")
				parsedResp := getOCSPResponse(rootCert, issuerCert, *reqType, *dir)
				linter.CheckOCSPResp(parsedResp)
			} else {
				fmt.Println("Stapled OCSP Response")
				parsedResp, err := ocsp.ParseResponse(ocspResp, issuerCert)
				if err != nil {
					fmt.Println(string(ocspResp))
					panic(err.Error())
				}
				linter.CheckOCSPResp(parsedResp)
			}

			tlsConn.Close()
		}
	}
}
