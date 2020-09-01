package main

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"github.com/golang/mock/gomock"
	"github.com/googleinterns/ocsp-response-linter/mocks"
	"github.com/googleinterns/ocsp-response-linter/testdata/resps"
	"golang.org/x/crypto/ocsp"
	"io/ioutil"
	"log"
	"os"
	"testing"
)

const (
	Resp = "./testdata/resps/oldfbresp"
	Cert = "./testdata/certs/google.der"
	URL  = "google.com:443"
)

// TestMain sets up the testing framework
func TestMain(m *testing.M) {
	// discard logging
	log.SetOutput(ioutil.Discard)
	os.Exit(m.Run())
}

type MockLinter struct{}

func (ml MockLinter) LintOCSPResp(resp *ocsp.Response) {}

// TestCheckFromFile tests checkFromFile, which reads an OCSP response file and lints it
func TestCheckFromFile(t *testing.T) {
	ctrl := gomock.NewController(t)

	// mocking ocsptools.ReadOCSPResp
	mt := mocks.NewMockToolsInterface(ctrl)
	mt.EXPECT().ReadOCSPResp(Resp).Return(&ocsp.Response{}, nil)

	// Alternate mocking scheme for linter, I want to keep this here just for memory
	// When linting becomes more complicated, I may need to revert to doing this
	// ml := mocks.NewMockLinterInterface(ctrl)
	// ml.EXPECT().LintOCSPResp(gomock.AssignableToTypeOf(&ocsp.Response{})).Return()

	ml := MockLinter{}

	t.Run("Happy path", func(t *testing.T) {
		err := checkFromFile(mt, ml, Resp)
		if err != nil {
			t.Errorf("Got error reading good response: %s", err.Error())
		}
	})

	mt.EXPECT().ReadOCSPResp(Cert).Return(nil, fmt.Errorf(""))

	t.Run("ReadOCSPResp errors", func(t *testing.T) {
		err := checkFromFile(mt, ml, Cert)
		if err == nil {
			t.Errorf("Should have gotten error when ReadOCSPResp errors")
		}
	})
}

// TestCheckFromFile tests checkFromCert, which parses a certificate file,
// gets the issuer URL from that certificate file, and fetches the OCSP response
func TestCheckFromCert(t *testing.T) {
	ctrl := gomock.NewController(t)

	ml := MockLinter{}

	mt := mocks.NewMockToolsInterface(ctrl)
	mt.EXPECT().ParseCertificateFile(Cert).Return(&x509.Certificate{}, nil)
	mt.EXPECT().GetIssuerCertFromLeafCert(gomock.AssignableToTypeOf(&x509.Certificate{})).Return(&x509.Certificate{}, nil)
	// I don't think there is value in actually specifying all these types
	mt.EXPECT().FetchOCSPResp(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(&ocsp.Response{}, nil)

	t.Run("Happy path", func(t *testing.T) {
		err := checkFromCert(mt, ml, Cert, false, "", "", crypto.SHA1)
		if err != nil {
			t.Errorf("Got error reading good certificate file: %s", err.Error())
		}
	})

	mt.EXPECT().ParseCertificateFile(Resp).Return(nil, fmt.Errorf(""))

	t.Run("ParseCertificateFile errors", func(t *testing.T) {
		err := checkFromCert(mt, ml, Resp, false, "", "", crypto.SHA1)
		if err == nil {
			t.Errorf("Should have gotten error when ParseCertificateFile errors")
		}
	})

	mt.EXPECT().ParseCertificateFile(Cert).Return(nil, nil)
	mt.EXPECT().GetIssuerCertFromLeafCert(nil).Return(nil, fmt.Errorf(""))

	t.Run("GetIssuerCertFromLeafCert errors", func(t *testing.T) {
		err := checkFromCert(mt, ml, Cert, false, "", "", crypto.SHA1)
		if err == nil {
			t.Errorf("Should have gotten error when GetIssuerCertFromLeafCert errors")
		}
	})

	mt.EXPECT().ParseCertificateFile(Cert).Return(nil, nil)
	mt.EXPECT().GetIssuerCertFromLeafCert(nil).Return(nil, nil)
	mt.EXPECT().FetchOCSPResp(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, fmt.Errorf(""))

	t.Run("FetchOCSPResp errors", func(t *testing.T) {
		err := checkFromCert(mt, ml, Cert, false, "", "", crypto.SHA1)
		if err == nil {
			t.Errorf("Should have gotten error when FetchOCSPResp errors")
		}
	})
}

// TestCheckFromURL tests checkFromURL, which gets the certificate chain
// and stapled OCSP response from a server URL, then depending on flags
// and the presence of a stapled response fetches an OCSP response
func TestCheckFromURL(t *testing.T) {
	ctrl := gomock.NewController(t)

	mockChain := []*x509.Certificate{
		{},
		nil,
	}

	ml := MockLinter{}

	mt := mocks.NewMockToolsInterface(ctrl)
	mt.EXPECT().GetCertChainAndStapledResp(gomock.Any()).Return(mockChain, nil, nil)
	mt.EXPECT().FetchOCSPResp(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(&ocsp.Response{}, nil)

	t.Run("Happy path", func(t *testing.T) {
		err := checkFromURL(mt, ml, URL, false, false, false, "", "", crypto.SHA1)
		if err != nil {
			t.Errorf("Got error from good URL: %s", err.Error())
		}
	})

	mt.EXPECT().GetCertChainAndStapledResp(gomock.Any()).Return(mockChain, resps.ByteArrayOCSPResp, nil)

	t.Run("Happy path with stapled OCSP Response", func(t *testing.T) {
		err := checkFromURL(mt, ml, URL, false, false, false, "", "", crypto.SHA1)
		if err != nil {
			t.Errorf("Got error with stapled OCSP Response: %s", err.Error())
		}
	})

	mt.EXPECT().GetCertChainAndStapledResp(gomock.Any()).Return(mockChain, []byte{1}, nil)

	t.Run("Bad byte array for OCSP Response", func(t *testing.T) {
		err := checkFromURL(mt, ml, URL, false, false, false, "", "", crypto.SHA1)
		if err == nil {
			t.Errorf("Should have gotten error parsing bad byte array into OCSP response")
		}
	})

	mt.EXPECT().GetCertChainAndStapledResp(gomock.Any()).Return(nil, nil, fmt.Errorf(""))

	t.Run("GetCertChainAndStapledResp errors", func(t *testing.T) {
		err := checkFromURL(mt, ml, URL, false, false, false, "", "", crypto.SHA1)
		if err == nil {
			t.Errorf("Should have gotten error when GetCertChainAndStapledResp errors")
		}
	})

	mt.EXPECT().GetCertChainAndStapledResp(gomock.Any()).Return(mockChain, nil, nil)
	mt.EXPECT().FetchOCSPResp(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, fmt.Errorf(""))

	t.Run("FetchOCSPResp errors", func(t *testing.T) {
		err := checkFromURL(mt, ml, URL, false, false, false, "", "", crypto.SHA1)
		if err == nil {
			t.Errorf("Should have gotten error when FetchOCSPResp errors")
		}
	})
}
