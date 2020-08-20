package ocsptools

import (
	"../linter"
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/grantae/certinfo"
	"golang.org/x/crypto/ocsp"
	"io/ioutil"
	"net/http"
)

// printCert prints the givern certificate using the external library github.com/grantae/certinfo
func PrintCert(cert *x509.Certificate) {
	result, err := certinfo.CertificateText(cert)
	if err != nil {
		panic(err.Error())
	}
	fmt.Print(result)
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
// rootCert is the root certificate (first certificate in the chain)
// issuerCert is the last certificate in the chain
// reqMethod is either GET or POST (TODO: change reqMethod to not be string)
func CreateOCSPReq(ocspURL string, rootCert *x509.Certificate, issuerCert *x509.Certificate, reqMethod string, hash crypto.Hash) *http.Request {
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

func CreateOCSPReqFromCert(certFile string, ocspURL string, reqMethod string, hash crypto.Hash) (*http.Request, *x509.Certificate) {
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
	issuerCert, err := GetCertFromIssuerURL(issuerURL)
	if err != nil {
		panic("Error getting certificate from issuer url: " + err.Error())
	}
	return CreateOCSPReq(ocspURL, parsedCert, issuerCert, reqMethod, hash), issuerCert
}

// getOCSPResponse constructs and sends an OCSP request then returns the OCSP response
func GetOCSPResponse(ocspReq *http.Request, dir string) []byte {
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

func ParseAndLint(ocspResp []byte, issuerCert *x509.Certificate) error {
	parsedResp, err := ocsp.ParseResponse(ocspResp, issuerCert)
	if err != nil {
		fmt.Println(string(ocspResp)) // for debugging, will remove
		return err
	}
	linter.CheckOCSPResp(parsedResp)
	return nil
}
