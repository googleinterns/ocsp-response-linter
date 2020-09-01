package main

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"golang.org/x/crypto/ocsp"
	"github.com/golang/mock/gomock"
	"github.com/googleinterns/ocsp-response-linter/mocks"
	"github.com/googleinterns/ocsp-response-linter/testdata/resps"
	"io/ioutil"
	"log"
	"os"
	"testing"
)

const (
	Resp = "./testdata/resps/oldfbresp"
	Cert = "./testdata/certs/google.der"
	// ExpiredCert = "./testdata/certs/expiredcert.der"
	// NoIssuingURLCert = "./testdata/certs/rootcert.der"
	URL = "google.com:443"
	// RevokedURL = "revoked.grc.com:443"
	// BadURL = "blah.blah.blah"
)

// TestMain sets up the testing framework
func TestMain(m *testing.M) {
	// discard logging
	log.SetOutput(ioutil.Discard)
	os.Exit(m.Run())
}

type MockLinter struct {}

func (ml MockLinter) LintOCSPResp(resp *ocsp.Response) {}

// TestCheckFromFile tests checkFromFile mocking ocsptools.ReadOCSPResp
func TestCheckFromFile(t *testing.T) {
	ctrl := gomock.NewController(t)

	mt := mocks.NewMockToolsInterface(ctrl)
	mt.EXPECT().ReadOCSPResp(Resp).Return(&ocsp.Response{}, nil)

	// ml := mocks.NewMockLinterInterface(ctrl)
	// ml.EXPECT().LintOCSPResp(gomock.AssignableToTypeOf(&ocsp.Response{})).Return()

	ml := MockLinter{}

	err := checkFromFile(mt, ml, Resp)
	if err != nil {
		t.Errorf("Got error reading good response: %s", err.Error())
	}

	mt.EXPECT().ReadOCSPResp(Cert).Return(nil, fmt.Errorf(""))

	err = checkFromFile(mt, ml, Cert)
	if err == nil {
		t.Errorf("Should have gotten error when ReadOCSPResp errors")
	}
}

// TestCheckFromFile tests checkFromFile mocking ocsptools functions
func TestCheckFromCert(t *testing.T) {
	ctrl := gomock.NewController(t)

	mt := mocks.NewMockToolsInterface(ctrl)
	mt.EXPECT().ParseCertificateFile(Cert).Return(&x509.Certificate{}, nil)
	mt.EXPECT().GetIssuerCertFromLeafCert(gomock.AssignableToTypeOf(&x509.Certificate{})).Return(&x509.Certificate{}, nil)
	// I'm not sure if there's any value actually specifying all these types
	mt.EXPECT().FetchOCSPResp(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(&ocsp.Response{}, nil)

	ml := MockLinter{}

	err := checkFromCert(mt, ml, Cert, false, "", "", crypto.SHA1)
	if err != nil {
		t.Errorf("Got error reading good certificate file: %s", err.Error())
	}

	mt.EXPECT().ParseCertificateFile(Resp).Return(nil, fmt.Errorf(""))

	err = checkFromCert(mt, ml, Resp, false, "", "", crypto.SHA1)
	if err == nil {
		t.Errorf("Should have gotten error reading file that is not a certificate")
	}

	mt.EXPECT().ParseCertificateFile(Cert).Return(nil, nil)
	mt.EXPECT().GetIssuerCertFromLeafCert(nil).Return(nil, fmt.Errorf(""))

	err = checkFromCert(mt, ml, Cert, false, "", "", crypto.SHA1)
	if err == nil {
		t.Errorf("Should have gotten error when GetIssuerCertFromLeafCert errors")
	}

	mt.EXPECT().ParseCertificateFile(Cert).Return(nil, nil)
	mt.EXPECT().GetIssuerCertFromLeafCert(nil).Return(nil, nil)
	mt.EXPECT().FetchOCSPResp(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, fmt.Errorf(""))

	err = checkFromCert(mt, ml, Cert, false, "", "", crypto.SHA1)
	if err == nil {
		t.Errorf("Should have gotten error when FetchOCSPResp errors")
	}
}

// TestCheckFromURL tests checkFromURL mocking ocsptools functions
func TestCheckFromURL(t *testing.T) {
	ctrl := gomock.NewController(t)

	mockChain := []*x509.Certificate {
		&x509.Certificate{},
		nil,
	}

	mt := mocks.NewMockToolsInterface(ctrl)
	mt.EXPECT().GetCertChainAndStapledResp(gomock.Any()).Return(mockChain, nil, nil)
	mt.EXPECT().FetchOCSPResp(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(&ocsp.Response{}, nil)

	ml := MockLinter{}

	err := checkFromURL(mt, ml, URL, false, false, false, "", "", crypto.SHA1)
	if err != nil {
		t.Errorf("Got error from good URL: %s", err.Error())
	}

	mt.EXPECT().GetCertChainAndStapledResp(gomock.Any()).Return(mockChain, resps.ByteArrayOCSPResp, nil)
	err = checkFromURL(mt, ml, URL, false, false, false, "", "", crypto.SHA1)
	if err != nil {
		t.Errorf("Got error with stapled OCSP Response: %s", err.Error())
	}

	mt.EXPECT().GetCertChainAndStapledResp(gomock.Any()).Return(mockChain, []byte{1,}, nil)
	err = checkFromURL(mt, ml, URL, false, false, false, "", "", crypto.SHA1)
	if err == nil {
		t.Errorf("Should have gotten error parsing bad byte array into OCSP response")
	}

	mt.EXPECT().GetCertChainAndStapledResp(gomock.Any()).Return(nil, nil, fmt.Errorf(""))
	err = checkFromURL(mt, ml, URL, false, false, false, "", "", crypto.SHA1)
	if err == nil {
		t.Errorf("Should have gotten error when GetCertChainAndStapledResp errors")
	}

	mt.EXPECT().GetCertChainAndStapledResp(gomock.Any()).Return(mockChain, nil, nil)
	mt.EXPECT().FetchOCSPResp(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, fmt.Errorf(""))
	err = checkFromURL(mt, ml, URL, false, false, false, "", "", crypto.SHA1)
	if err == nil {
		t.Errorf("Should have gotten error when FetchOCSPResp errors")
	}
}
