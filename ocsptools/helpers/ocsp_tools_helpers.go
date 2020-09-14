package helpers

//go:generate mockgen -source=ocsp_tools_helpers.go -destination=../../mocks/helpersmock/mock_ocsptoolshelpers.go -package=helpersmock

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/ocsp"
	"io/ioutil"
	"net/http"
	"time"
)

const (
	RespTimeLimit    = "10s" // Time limit for OCSP response to be served
	TimeoutInSeconds = 20    // Time limit for http response before timeout
)

// HelpersInterface is an interface for the functions that can be used from this file
type HelpersInterface interface {
	GetCertFromIssuerURL(string) (*x509.Certificate, error)
	CreateOCSPReq(string, *x509.Certificate, *x509.Certificate, string, crypto.Hash) (*http.Request, error)
	GetOCSPResp(*http.Request) ([]byte, error)
}

// Helpers is an exported struct of type HelpersInterface
type Helpers struct{}

// GetCertFromIssuerURL takes an issuerURL and sends a GET request to the URL to retrieve its certificate
// Assumes that sending a GET request to the provided URL will return its certificate
func (h Helpers) GetCertFromIssuerURL(issuerURL string) (*x509.Certificate, error) {
	httpReq, err := http.NewRequest(http.MethodGet, issuerURL, nil)
	if err != nil {
		return nil, fmt.Errorf("Error creating http request: %w", err)
	}

	httpClient := &http.Client{
		Timeout: TimeoutInSeconds * time.Second,
	}
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("Error sending http request: %w", err)
	}

	defer resp.Body.Close()

	cert, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Error reading http response body: %w", err)
	}

	parsedCert, err := x509.ParseCertificate(cert)
	if err != nil {
		return nil, fmt.Errorf("Error parsing certificate: %w", err)
	}

	return parsedCert, nil
}

// CreateOCSPReq creates an OCSP request using either GET or POST (see IETF RFC 6960)
// leafCert is the root certificate (first certificate in the chain)
// issuerCert is the certificate of the issuer of the leafCert
// reqMethod is either GET or POST
// hash is the hash to use to encode the request (either SHA1 or SHA256 right now)
func (h Helpers) CreateOCSPReq(ocspURL string, leafCert *x509.Certificate, issuerCert *x509.Certificate, reqMethod string, hash crypto.Hash) (*http.Request, error) {
	if ocspURL == "" {
		// leafCert probably is an intermediary
		// may not be required to have an OCSP responder
		if len(leafCert.OCSPServer) == 0 {
			return nil, fmt.Errorf("Certificate does not have an OCSP server")
		}
		ocspURL = leafCert.OCSPServer[0] // URL of OCSP Responder for this certificate
	}

	ocspReq, err := ocsp.CreateRequest(leafCert, issuerCert, &ocsp.RequestOptions{
		Hash: hash,
	})
	if err != nil {
		return nil, fmt.Errorf("Failed creating OCSP Request: %w", err)
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
		return nil, fmt.Errorf("Failed to create HTTP request: %w", err)
	}

	httpReq.Header.Add("Content-Type", "application/ocsp-request")
	httpReq.Header.Add("Accept", "application/ocsp-response")

	return httpReq, nil
}

// GetOCSPResp takes an OCSP request in the form of an HTTP request sends it and returns the response
// It also times the response time, and if it's over 10 seconds, then it has failed a verification
func (h Helpers) GetOCSPResp(ocspReq *http.Request) ([]byte, error) {
	startTime := time.Now()

	httpClient := &http.Client{
		Timeout: TimeoutInSeconds * time.Second,
	}
	httpResp, err := httpClient.Do(ocspReq)
	if err != nil {
		return nil, fmt.Errorf("Error sending http request: %w", err)
	}

	endTime := time.Now()
	limit, err := time.ParseDuration(RespTimeLimit)
	if err != nil {
		panic(err.Error()) // error really shouldn't happen
	}

	// Verification (source from Apple Lint 08)
	if endTime.Sub(startTime) > limit {
		fmt.Printf("Server took longer than %s to respond \n", RespTimeLimit)
	}

	defer httpResp.Body.Close()
	ocspResp, err := ioutil.ReadAll(httpResp.Body)
	if err != nil {
		// if HTTP 405 results from GET request, need to say that's a lint
		return nil, fmt.Errorf("Error reading http response body: %w", err)
	}

	return ocspResp, nil
}
