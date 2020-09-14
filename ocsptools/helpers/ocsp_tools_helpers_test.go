package helpers

import (
	"crypto"
	"crypto/x509"
	"io/ioutil"
	"net/http"
	"testing"
)

const (
	GoodCert       = "../../testdata/certs/google.der"       // good certificate
	GoodIssuerCert = "../../testdata/certs/googleissuer.der" // issuer certificate for good certificate
	URL            = "google.com:443"                        // sample URL
)

// TestCreateOCSPReq tests CreateOCSPReq, which builds an OCSP request to check
// the revocation of leafCert using different user parameters
func TestCreateOCSPReq(t *testing.T) {
	h := Helpers{}

	// can't import ocsptools or else there is a cycle
	lcert, _ := ioutil.ReadFile(GoodCert)
	leafCert, _ := x509.ParseCertificate(lcert)

	icert, _ := ioutil.ReadFile(GoodIssuerCert)
	issuerCert, _ := x509.ParseCertificate(icert)

	t.Run("Happy path", func(t *testing.T) {
		_, err := h.CreateOCSPReq("", leafCert, issuerCert, http.MethodGet, crypto.SHA1)
		if err != nil {
			t.Errorf("Got error with good parameters: %s", err.Error())
		}
	})

	t.Run("Specify OCSP URL and use POST", func(t *testing.T) {
		httpReq, err := h.CreateOCSPReq(URL, leafCert, issuerCert, http.MethodPost, crypto.SHA1)
		if err != nil {
			t.Errorf("Got error with good parameters: %s", err.Error())
		}

		if httpReq.Method != http.MethodPost {
			t.Errorf("HTTP request does not use POST when specified to do so")
		}

		serverURL := httpReq.URL.String()
		if URL != serverURL {
			t.Errorf("HTTP request does not use specified OCSP server url: %s, instead uses: %s", URL, serverURL)
		}
	})

	t.Run("Bad issuer certificate", func(t *testing.T) {
		_, err := h.CreateOCSPReq("", leafCert, &x509.Certificate{}, http.MethodGet, crypto.SHA1)
		if err == nil {
			t.Errorf("Should have gotten error with bad issuer certificate")
		}
	})

	leafCert.OCSPServer = nil
	t.Run("Certificate without OCSP Server", func(t *testing.T) {
		_, err := h.CreateOCSPReq("", leafCert, issuerCert, http.MethodGet, crypto.SHA1)
		if err == nil {
			t.Errorf("Should have gotten error with certificate with empty OCSPServer field")
		}
	})
}
