package ocsptools

//go:generate mockgen -source=ocsp_tools.go -destination=../mocks/toolsmock/mock_ocsptools.go -package=toolsmock

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/googleinterns/ocsp-response-linter/ocsptools/helpers"
	"github.com/grantae/certinfo"
	"golang.org/x/crypto/ocsp"
	"io/ioutil"
)

type ToolsInterface interface {
	ReadOCSPResp(string) (*ocsp.Response, error)
	ParseCertificateFile(string) (*x509.Certificate, error)
	GetIssuerCertFromLeafCert(helpers.HelpersInterface, *x509.Certificate) (*x509.Certificate, error)
	FetchOCSPResp(helpers.HelpersInterface, string, string, *x509.Certificate, *x509.Certificate, string, crypto.Hash) (*ocsp.Response, error)
	GetCertChainAndStapledResp(string) ([]*x509.Certificate, []byte, error)
}

type Tools struct{}

// PrintCert prints the given certificate using the external library github.com/grantae/certinfo
func PrintCert(cert *x509.Certificate) error {
	result, err := certinfo.CertificateText(cert)
	if err != nil {
		return fmt.Errorf("failed converting certificate for printing: %w", err)
	}
	fmt.Print(result)
	return nil
}

// ReadOCSPResp takes a path to an OCSP response file and reads and parses it
func (t Tools) ReadOCSPResp(ocspRespFile string) (*ocsp.Response, error) {
	ocspResp, err := ioutil.ReadFile(ocspRespFile)
	if err != nil {
		return nil, fmt.Errorf("Error reading file: %w", err)
	}
	parsedResp, err := ocsp.ParseResponse(ocspResp, nil)
	if err != nil {
		return nil, fmt.Errorf("Error parsing OCSP Response: %w", err)
	}

	return parsedResp, err
}

// ParseCertificateFile takes a path to a certificate and returns a parsed certificate
func (t Tools) ParseCertificateFile(certFile string) (*x509.Certificate, error) {
	cert, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("Error reading certificate file: %w", err)
	}

	parsedCert, err := x509.ParseCertificate(cert)
	if err != nil {
		return nil, fmt.Errorf("Error parsing certificate file: %w", err)
	}

	return parsedCert, nil
}

// GetIssuerCertFromLeafCert takes in a leaf certificate, reads its issuing certificate url field
// and then calls GetCertFromIssuerURL to return the issuer certificate
func (t Tools) GetIssuerCertFromLeafCert(h helpers.HelpersInterface, leafCert *x509.Certificate) (*x509.Certificate, error) {
	if len(leafCert.IssuingCertificateURL) == 0 {
		return nil, fmt.Errorf("Certificate has no issuing certificate url field")
	}

	issuerURL := leafCert.IssuingCertificateURL[0]

	issuerCert, err := h.GetCertFromIssuerURL(issuerURL)
	if err != nil {
		return nil, fmt.Errorf("Error getting certificate from issuer url %s: %w", issuerURL, err)
	}

	return issuerCert, nil
}

// FetchOCSPResp uses the functions above to create and send an OCSP Request
// and then parse the returned OCSP response
// If dir is specified, it will also write the OCSP Response to dir
func (t Tools) FetchOCSPResp(h helpers.HelpersInterface, ocspURL string, dir string, leafCert *x509.Certificate, issuerCert *x509.Certificate, reqMethod string, hash crypto.Hash) (*ocsp.Response, error) {
	ocspReq, err := h.CreateOCSPReq(ocspURL, leafCert, issuerCert, reqMethod, hash)
	if err != nil {
		return nil, fmt.Errorf("Error creating OCSP Request: %w", err)
	}

	ocspResp, err := h.GetOCSPResp(ocspReq)
	if err != nil {
		return nil, fmt.Errorf("Error getting OCSP Response: %w", err)
	}

	if dir != "" {
		err := ioutil.WriteFile(dir, ocspResp, 0644)
		if err != nil {
			return nil, fmt.Errorf("Error writing OCSP Response to file %s: %w", dir, err)
		}
	}

	parsedResp, err := ocsp.ParseResponse(ocspResp, issuerCert)
	if err != nil {
		return nil, fmt.Errorf("Error parsing OCSP response: %w", err)
	}

	return parsedResp, nil
}

// GetCertChain takes in a serverURL, attempts to build a tls connection to it
// and returns the resulting certificate chain and stapled OCSP Response
func (t Tools) GetCertChainAndStapledResp(serverURL string) ([]*x509.Certificate, []byte, error) {
	config := &tls.Config{}

	tlsConn, err := t.Dial("tcp", serverURL, config)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to %s: %w", serverURL, err)
	}

	defer tlsConn.Close()

	// shouldn't happen since Config.InsecureSkipVerify is false, just being overly careful
	if len(tlsConn.ConnectionState().VerifiedChains) == 0 {
		return nil, nil, fmt.Errorf("No verified chain from sever to system root certificates")
	}

	certChain := tlsConn.ConnectionState().VerifiedChains[0]

	if len(certChain) == 0 {
		// Certificate chain should never be empty but just being overly careful
		return nil, nil, fmt.Errorf("No certificate present for %s", serverURL)
	} else if len(certChain) == 1 {
		// Server should never send a root certificate but just being overly careful
		return nil, nil, fmt.Errorf("Certificate for %s is a root certificate", serverURL)
	}

	// ocspResp is nil if there is no stapled OCSP Response
	ocspResp := tlsConn.OCSPResponse()

	return certChain, ocspResp, nil
}
