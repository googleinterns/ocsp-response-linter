package ocsptools

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"github.com/golang/mock/gomock"
	"github.com/googleinterns/ocsp-response-linter/linter"
	"github.com/googleinterns/ocsp-response-linter/mocks/helpersmock"
	"github.com/googleinterns/ocsp-response-linter/testdata/resps"
	"golang.org/x/crypto/ocsp"
	"testing"
)

const (
	GoodResp = "../testdata/resps/oldfbresp"
	GoodCert = "../testdata/certs/google.der"
	GoodIssuerCert = "../testdata/certs/googleissuer.der"
	NoIssuerURLCert = "../testdata/certs/rootcert.der"
	BadPath  = "blah///blah/blah.blah"
	URL = "google.com:443"
)

// TestReadOCSPResp tests ReadOCSPResp, which reads and parses an OCSP response file
func TestReadOCSPResp(t *testing.T) {
	tools := Tools{}

	t.Run("Happy path", func(t *testing.T) {
		parsedResp, err := tools.ReadOCSPResp(GoodResp)
		if err != nil {
			t.Errorf("Got error reading good response: %s", err.Error())
		}

		// check if OCSP Response status was parsed correctly
		status := parsedResp.Status
		if status != ocsp.Good {
			t.Errorf("Parsed OCSP Response should have status good but instead has status: %s",
				linter.StatusIntMap[status])
		}
	})

	t.Run("Bad file path", func(t *testing.T) {
		_, err := tools.ReadOCSPResp(BadPath)
		if err == nil {
			t.Errorf("Should have gotten error reading bad file path")
		}
	})

	t.Run("Reading file that is not OCSP Response", func(t *testing.T) {
		_, err := tools.ReadOCSPResp(GoodCert)
		if err == nil {
			t.Errorf("Should have gotten error reading file that is not an OCSP response")
		}
	})
}

// TestParseCertificateFile tests ParseCertificateFile, which reads and parses a certificate file
func TestParseCertificateFile(t *testing.T) {
	tools := Tools{}

	t.Run("Happy path", func(t *testing.T) {
		parsedCert, err := tools.ParseCertificateFile(GoodCert)
		if err != nil {
			t.Errorf("Got error reading good certificate: %s", err.Error())
		}

		if len(parsedCert.OCSPServer) == 0 {
			t.Errorf("Parsed certificate has no OCSPServer field when it should")
		}

		if len(parsedCert.IssuingCertificateURL) == 0 {
			t.Errorf("Parsed certificate has no IssuingCertificateURL field when it should")
		}
	})

	t.Run("Bad file path", func(t *testing.T) {
		_, err := tools.ParseCertificateFile(BadPath)
		if err == nil {
			t.Errorf("Should have gotten error reading bad file path")
		}
	})

	t.Run("Reading file that is not certificate", func(t *testing.T) {
		_, err := tools.ParseCertificateFile(GoodResp)
		if err == nil {
			t.Errorf("Should have gotten error reading file that is not a certificate")
		}
	})
}

// TestGetIssuerCertFromLeafCert tests GetIssuerCertFromLeafCert, which checks for the 
// IssuingCertificateURL field in the given leaf certificate, and if it's present,
// sends a GET request to that URL and parses the response into a certificate
func TestGetIssuerCertFromLeafCert(t *testing.T) {
	tools := Tools{}
	goodCert, _ := tools.ParseCertificateFile(GoodCert)

	ctrl := gomock.NewController(t)

	h := helpersmock.NewMockHelpersInterface(ctrl)
	h.EXPECT().GetCertFromIssuerURL(gomock.Any()).Return(&x509.Certificate{}, nil)

	t.Run("Happy path", func(t *testing.T) {
		_, err := tools.GetIssuerCertFromLeafCert(h, goodCert)
		if err != nil {
			t.Errorf("Got error getting issuer certificate from a good certificate: %s", err.Error())
		}
	})

	noURLCert, _ := tools.ParseCertificateFile(NoIssuerURLCert)
	t.Run("Certificate with no issuer URL", func(t *testing.T) {
		_, err := tools.GetIssuerCertFromLeafCert(h, noURLCert)
		if err == nil {
			t.Errorf("Should have gotten error with certificate with empty issuer URL field")
		}
	})

	h.EXPECT().GetCertFromIssuerURL(gomock.Any()).Return(nil, fmt.Errorf(""))
	t.Run("Bad issuer URL", func(t *testing.T) {
		_, err := tools.GetIssuerCertFromLeafCert(h, goodCert)
		if err == nil {
			t.Errorf("Should have gotten error when GetCertFromIssuerURL errors")
		}
	})
}

// TestFetchOCSPResp tests FetchOCSPResp which fetches the OCSP Response using
// helpers CreateOCSPReq and GetOCSPResp
// FetchOCSPResp also writes the OCSP response to a directory if specified
func TestFetchOCSPResp(t *testing.T) {
	tools := Tools{}

	ctrl := gomock.NewController(t)

	h := helpersmock.NewMockHelpersInterface(ctrl)

	h.EXPECT().CreateOCSPReq(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil)
	h.EXPECT().GetOCSPResp(gomock.Any()).Return(resps.ByteArrayOCSPResp, nil)
	t.Run("Happy path", func(t *testing.T) {
		_, err := tools.FetchOCSPResp(h, "", "", nil, nil, "", crypto.SHA1)
		if err != nil {
			t.Errorf("Got error fetching OCSP response with good parameters: %s", err.Error())
		}
	})

	h.EXPECT().CreateOCSPReq(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, fmt.Errorf(""))
	t.Run("CreateOCSPReq errors", func(t *testing.T) {
		_, err := tools.FetchOCSPResp(h, "", "", nil, nil, "", crypto.SHA1)
		if err == nil {
			t.Error("Should have gotten error when CreateOCSPReq errors")
		}
	})

	h.EXPECT().CreateOCSPReq(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil)
	h.EXPECT().GetOCSPResp(gomock.Any()).Return(nil, fmt.Errorf(""))
	t.Run("GetOCSPResp errors", func(t *testing.T) {
		_, err := tools.FetchOCSPResp(h, "", "", nil, nil, "", crypto.SHA1)
		if err == nil {
			t.Error("Should have gotten error when GetOCSPResp errors")
		}
	})

	h.EXPECT().CreateOCSPReq(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil)
	h.EXPECT().GetOCSPResp(gomock.Any()).Return(resps.ByteArrayOCSPResp, nil)
	t.Run("Bad directory", func(t *testing.T) {
		_, err := tools.FetchOCSPResp(h, "", BadPath, nil, nil, "", crypto.SHA1)
		if err == nil {
			t.Error("Should have gotten error with bad directory path")
		}
	})

	h.EXPECT().CreateOCSPReq(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil)
	h.EXPECT().GetOCSPResp(gomock.Any()).Return([]byte{1,}, nil)
	t.Run("Bad OCSP Response", func(t *testing.T) {
		_, err := tools.FetchOCSPResp(h, "", "", nil, nil, "", crypto.SHA1)
		if err == nil {
			t.Error("Should have gotten error with bad, unparsable OCSP response")
		}
	})
}
