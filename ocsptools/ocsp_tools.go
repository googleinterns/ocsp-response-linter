package ocsptools

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/googleinterns/ocsp-response-linter/linter"
	"github.com/grantae/certinfo"
	"golang.org/x/crypto/ocsp"
	"io/ioutil"
	"net/http"
)

// printCert prints the givern certificate using the external library github.com/grantae/certinfo
func PrintCert(cert *x509.Certificate) error {
	result, err := certinfo.CertificateText(cert)
	if err != nil {
		return fmt.Errorf("failed converting certificate for printing: %w", err)
	}
	fmt.Print(result)
	return nil
}

func GetCertFromIssuerURL(issuerURL string) (*x509.Certificate, error) {
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
// leafCert is the root certificate (first certificate in the chain)
// issuerCert is the last certificate in the chain
// reqMethod is either GET or POST (TODO: change reqMethod to not be string)
func CreateOCSPReq(ocspURL string, leafCert *x509.Certificate, issuerCert *x509.Certificate, reqMethod string, hash crypto.Hash) (*http.Request, error) {
	if ocspURL == "" {
		ocspURL = leafCert.OCSPServer[0]
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

func CreateOCSPReqFromCert(certFile string, ocspURL string, reqMethod string, hash crypto.Hash) (*http.Request, *x509.Certificate, error) {
	cert, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, nil, fmt.Errorf("Error reading certificate file: %w", err)
	}

	parsedCert, err := x509.ParseCertificate(cert)
	if err != nil {
		return nil, nil, fmt.Errorf("Error parsing certificate file: %w", err)
	}

	if len(parsedCert.IssuingCertificateURL) == 0 {
		return nil, nil, fmt.Errorf("Certificate read from file %s has no issuing certificate url", certFile)
	}

	issuerURL := parsedCert.IssuingCertificateURL[0]
	issuerCert, err := GetCertFromIssuerURL(issuerURL)
	if err != nil {
		return nil, nil, fmt.Errorf("Error getting certificate from issuer url: %w", err)
	}

	ocspReq, err := CreateOCSPReq(ocspURL, parsedCert, issuerCert, reqMethod, hash)
	if err != nil {
		return nil, issuerCert, fmt.Errorf("Error creating OCSP request from certificate file: %w", err)
	}

	return ocspReq, issuerCert, nil
}

// getOCSPResponse constructs and sends an OCSP request then returns the OCSP response
func GetOCSPResponse(ocspReq *http.Request) ([]byte, error) {
	httpClient := &http.Client{}
	httpResp, err := httpClient.Do(ocspReq)
	if err != nil {
		return nil, fmt.Errorf("Error sending http request: %w", err)
	}

	defer httpResp.Body.Close()
	ocspResp, err := ioutil.ReadAll(httpResp.Body)
	if err != nil {
		// if HTTP 405 results from GET request, need to say that's a lint
		return nil, fmt.Errorf("Error reading http response body: %w", err)
	}

	return ocspResp, nil
}

func ParseAndLint(ocspResp []byte, issuerCert *x509.Certificate) error {
	parsedResp, err := ocsp.ParseResponse(ocspResp, issuerCert)
	if err != nil {
		fmt.Println(string(ocspResp)) // for debugging, will remove
		return fmt.Errorf("Error parsing OCSP response: %w", err)
	}
	linter.LintOCSPResp(parsedResp)
	return nil
}
