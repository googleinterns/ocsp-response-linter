package ocsptools

import (
	"github.com/googleinterns/ocsp-response-linter/linter"
	"golang.org/x/crypto/ocsp"
	"testing"
)

const (
	GoodResp = "../testdata/resps/oldfbresp"
	GoodCert = "../testdata/certs/google.der"
	// ExpiredCert = "./testdata/certs/expiredcert.der"
	// NoIssuingURLCert = "./testdata/certs/rootcert.der"
	// RevokedURL = "revoked.grc.com:443"
	// BadURL = "blah.blah.blah"
)

// TestReadOCSPResp tests ReadOCSPResp
// We are not mocking ocsp.ParseResponse because we depend on that working
func TestReadOCSPResp(t *testing.T) {
	tools := Tools{}

	t.Run("Happy path", func(t *testing.T) {
		parsed_resp, err := tools.ReadOCSPResp(GoodResp)
		if err != nil {
			t.Errorf("Got error reading good response: %s", err.Error())
		}

		// check if OCSP Response status was parsed correctly
		status := parsed_resp.Status
		if status != ocsp.Good {
			t.Errorf("Parsed OCSP Response should have status good but instead has status: %s", 
				linter.StatusIntMap[status])
		}
	})

	t.Run("Reading file that is not OCSP Response", func(t *testing.T) {
		_, err := tools.ReadOCSPResp(GoodCert)
		if err == nil {
			t.Errorf("Should have gotten error reading file that is not an OCSP response")
		}
	})
}