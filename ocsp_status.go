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

func getCertFromIssuerURL(issuerURL string) (*x509.Certificate, error) {
	resp, err := http.Get(issuerURL)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	cert, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	parsedCert, err := x509.ParseCertificate(cert)
	if err != nil {
		return nil, err
	}

	return parsedCert, nil
}

// createOCSPReq creates an OCSP request using either GET or POST (see IETF RFC 6960)
// rootCert is the root certificate (first certificate in the chain)
// issuerCert is the last certificate in the chain
// reqMethod is either GET or POST (TODO: change reqMethod to not be string)
func createOCSPReq(ocspURL string, rootCert *x509.Certificate, issuerCert *x509.Certificate, reqMethod string, hash crypto.Hash) *http.Request {
	// not sure what to do if there are multiple here
	// make a request for each?
	if ocspURL == "" {
		ocspURL = rootCert.OCSPServer[0]
	}

	ocspReq, err := ocsp.CreateRequest(rootCert, issuerCert, &ocsp.RequestOptions{
		Hash: hash,
	})
	if err != nil {
		panic(err.Error())
	}

	body := bytes.NewBuffer(ocspReq)

	if reqMethod == http.MethodGet {
		// Do I need to worry about line breaks?
		enc := base64.StdEncoding.EncodeToString(ocspReq)
		ocspURL += "/" + enc
		body = bytes.NewBuffer(nil) // body = nil runs into errors
	}

	httpReq, err := http.NewRequest(reqMethod, ocspURL, body)
	if err != nil {
		panic(err.Error())
	}

	httpReq.Header.Add("Content-Type", "application/ocsp-request")
	httpReq.Header.Add("Accept", "application/ocsp-response")

	return httpReq
}

func createOCSPReqFromCert(certFile string, ocspURL string, reqMethod string, hash crypto.Hash) (*http.Request, *x509.Certificate) {
	cert, err := ioutil.ReadFile(certFile)
	if err != nil {
		panic("Error reading certificate file: " + err.Error())
	}

	parsedCert, err := x509.ParseCertificate(cert)
	if err != nil {
		panic("Error parsing certificate: " + err.Error())
	}

	if len(parsedCert.IssuingCertificateURL) == 0 {
		panic("Provided certificate has no issuing certificate url")
	}

	issuerURL := parsedCert.IssuingCertificateURL[0]
	issuerCert, err := getCertFromIssuerURL(issuerURL)
	if err != nil {
		panic("Error getting certificate from issuer url: " + err.Error())
	}
	return createOCSPReq(ocspURL, parsedCert, issuerCert, reqMethod, hash), issuerCert
}

// getOCSPResponse constructs and sends an OCSP request then returns the OCSP response
func getOCSPResponse(ocspReq *http.Request, dir string) []byte {
	httpClient := &http.Client{}
	httpResp, err := httpClient.Do(ocspReq)
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

	return ocspResp
}

func lintFile(respFile string) {
	ocspResp, err := ioutil.ReadFile(respFile)
	if err != nil {
		panic("Error reading OCSP Response file: " + err.Error())
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

func parseAndLint(ocspResp []byte, issuerCert *x509.Certificate) error {
	parsedResp, err := ocsp.ParseResponse(ocspResp, issuerCert)
	if err != nil {
		fmt.Println(string(ocspResp)) // for debugging, will remove
		return err
	}
	linter.CheckOCSPResp(parsedResp)
	return nil
}

func checkFromCert(certFile string, get bool, ocspURL string, dir string, hash crypto.Hash) error {
	reqMethod := http.MethodPost
	if get {
		reqMethod = http.MethodGet
	}

	ocspReq, issuerCert := createOCSPReqFromCert(certFile, ocspURL, reqMethod, hash)
	ocspResp := getOCSPResponse(ocspReq, dir)

	return parseAndLint(ocspResp, issuerCert)

}

func checkFromURL(serverURL string, print bool, get bool, ocspURL string, dir string, hash crypto.Hash) error {
	tlsConn := createConn(serverURL)

	certChain := tlsConn.ConnectionState().PeerCertificates
	rootCert := certChain[0]
	issuerCert := certChain[len(certChain)-1]

	if print {
		printCert(rootCert)
	}

	ocspResp := tlsConn.OCSPResponse()
	tlsConn.Close()

	if ocspResp == nil {
		fmt.Println("No OCSP response stapled")

		method := http.MethodPost
		if get {
			method = http.MethodGet
		}

		ocspReq := createOCSPReq(ocspURL, rootCert, issuerCert, method, hash)
		ocspResp = getOCSPResponse(ocspReq, dir)

		return parseAndLint(ocspResp, issuerCert)
	} else {
		fmt.Println("Stapled OCSP Response")
		return parseAndLint(ocspResp, issuerCert)
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
