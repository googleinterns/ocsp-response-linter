package main

import (
	"bytes"
	"encoding/base64"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"github.com/grantae/certinfo"
	"fmt"
	"flag"
	"golang.org/x/crypto/ocsp"
	"net/http"
	"io/ioutil"
	"./linter"
)

func create_conn(cert_url string) *tls.Conn {
	config := &tls.Config{

	}

	tls_conn, err := tls.Dial("tcp", cert_url, config)
	if err != nil {
		panic("failed to connect: " + err.Error())
	}

	err = tls_conn.Handshake()
	if err != nil {
		panic("handshake failed: " + err.Error())
	}

	return tls_conn
}

func print_cert(cert *x509.Certificate) {
	result, err := certinfo.CertificateText(cert)
	if err != nil {
		panic(err.Error())
	}
	fmt.Print(result)
}

func create_ocsp_req(root_cert *x509.Certificate, issuer_cert *x509.Certificate, req_type string) *http.Request {
	// not sure what to do if there are multiple here
	// make a request for each?
	ocsp_url := root_cert.OCSPServer[0]

	// TODO: Look into Request Options
	ocsp_req, err := ocsp.CreateRequest(root_cert, issuer_cert, &ocsp.RequestOptions{
		Hash: crypto.SHA1,
	})
	if err != nil {
		panic(err.Error())
	}

	body := bytes.NewBuffer(ocsp_req)

	if req_type == http.MethodGet {
		// Do I need to worry about line breaks?
		enc := base64.StdEncoding.EncodeToString(ocsp_req)
		ocsp_url += "/" + enc
		body = bytes.NewBuffer(nil) // body = nil runs into errors
	}

	http_req, err := http.NewRequest(req_type, ocsp_url, body)
	if err != nil {
		panic(err.Error())
	}

	http_req.Header.Add("Content-Type", "application/ocsp-request")
    http_req.Header.Add("Accept", "application/ocsp-response")

    return http_req
}

func parse_ocsp_resp(ocsp_resp []byte, issuer_cert *x509.Certificate) {
	// ocsp.ParseResponse validates signature with issuer_cert
	parsed_resp, err := ocsp.ParseResponse(ocsp_resp, issuer_cert)
    if err != nil {
    	fmt.Println(string(ocsp_resp))
        panic(err.Error())
    }
    linter.Check_Ocsp_Resp(parsed_resp)
}

func send_ocsp_req(root_cert *x509.Certificate, issuer_cert *x509.Certificate, req_type string, dir string) {
	http_req := create_ocsp_req(root_cert, issuer_cert, req_type)

    httpClient := &http.Client{}
    http_resp, err := httpClient.Do(http_req)
    if err != nil {
		panic(err.Error())
	}

	defer http_resp.Body.Close()
    ocsp_resp, err := ioutil.ReadAll(http_resp.Body)
    if err != nil {
    	// if HTTP 405 results from GET request, need to say that's a lint
        panic(err.Error())
    }

    if dir != "" {
    	err := ioutil.WriteFile(dir, ocsp_resp, 0644)
    	if err != nil {
    		panic("Error writing to file: " + err.Error())
    	}
    }

    parse_ocsp_resp(ocsp_resp, issuer_cert)
}

func main() {
	should_print := flag.Bool("print", false, "Whether to print certificate or not")
	dir := flag.String("dir", "", "Where to write certificate, if blank don't write")
	req_type := flag.String("type", http.MethodPost, "Whether to use GET or POST for OCSP request")
	in := flag.Bool("in", false, "Whether to read in a certificate or not")

	flag.Parse()

	if *in {
		resp_files := flag.Args()

		for _, resp_file := range resp_files {
			ocsp_resp, err := ioutil.ReadFile(resp_file)
			if err != nil {
				panic("Error reading file: " + err.Error())
			}
			// can't check signature w/o outside knowledge of who the issuer should be
			// TODO: add functionality so user can specify who the issuer is
			parse_ocsp_resp(ocsp_resp, nil)
		}
	} else {
		cert_urls := flag.Args()

		for _, cert_url := range cert_urls {
			tls_conn := create_conn(cert_url)

			// TODO: Print certificates to directory
			cert_chain := tls_conn.ConnectionState().PeerCertificates
			root_cert := cert_chain[0]
			issuer_cert := cert_chain[len(cert_chain) - 1]

			if (*should_print) {
				print_cert(root_cert)
			}

			ocsp_resp := tls_conn.OCSPResponse()

			if ocsp_resp == nil {
				fmt.Println("No OCSP response stapled")
				send_ocsp_req(root_cert, issuer_cert, *req_type, *dir)
			} else {
				fmt.Println("Stapled OCSP Response")
				parse_ocsp_resp(ocsp_resp, issuer_cert)
			}

			tls_conn.Close()
		}
	}		
}
