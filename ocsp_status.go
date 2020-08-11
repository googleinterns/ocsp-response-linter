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
	// "errors"
)

func createConn(certURL string) *tls.Conn {
	config := &tls.Config{}

	tlsConn, err := tls.Dial("tcp", certURL, config)
	if err != nil {
		panic("failed to connect: " + err.Error())
	}

	err = tlsConn.Handshake()
	if err != nil {
		panic("handshake failed: " + err.Error())
	}

	return tlsConn
}

func printCert(cert *x509.Certificate) {
	result, err := certinfo.CertificateText(cert)
	if err != nil {
		panic(err.Error())
	}
	fmt.Print(result)
}

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

func parseOCSPResp(ocspResp []byte, issuerCert *x509.Certificate) {
	// ocsp.ParseResponse validates signature with issuerCert
	parsedResp, err := ocsp.ParseResponse(ocspResp, issuerCert)
	if err != nil {
		fmt.Println(string(ocspResp))
		panic(err.Error())
	}
	linter.CheckOCSPResp(parsedResp)
}

func sendOCSPReq(rootCert *x509.Certificate, issuerCert *x509.Certificate, reqType string, dir string) {
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

	parseOCSPResp(ocspResp, issuerCert)
}

func main() {
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
			parseOCSPResp(ocspResp, nil)
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
				sendOCSPReq(rootCert, issuerCert, *reqType, *dir)
			} else {
				fmt.Println("Stapled OCSP Response")
				parseOCSPResp(ocspResp, issuerCert)
			}

			tlsConn.Close()
		}
	}
}
