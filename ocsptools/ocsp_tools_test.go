package ocsptools

import (
	"github.com/googleinterns/ocsp-response-linter/linter"
	"golang.org/x/crypto/ocsp"
	"testing"
)

const (
	GoodResp = "../testdata/resps/oldfbresp"
	GoodCert = "../testdata/certs/google.der"
)

// TestReadOCSPResp tests ReadOCSPResp
// We are not mocking ocsp.ParseResponse because we depend on that working
func TestReadOCSPResp(t *testing.T) {
	tools := Tools{}
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

	_, err = tools.ReadOCSPResp(GoodCert)
	if err == nil {
		t.Errorf("Should have gotten error reading file that is not an OCSP response")
	}
}