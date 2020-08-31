package main

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"golang.org/x/crypto/ocsp"
	"github.com/golang/mock/gomock"
	"github.com/googleinterns/ocsp-response-linter/mocks"
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
	// GoodURL = "google.com:443"
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

// TestCheckFromURL tests checkFromURL
// func TestCheckFromURL(t *testing.T) {
// 	ctrl := gomock.NewController(t)
// 	ml := mocks.NewMockLinterInterface(ctrl)
// 	ml.EXPECT().LintOCSPResp(gomock.AssignableToTypeOf(&ocsp.Response{})).Return().AnyTimes()

// 	err := checkFromURL(ml, GoodURL, false, false, false, "", "", crypto.SHA1)
// 	if err != nil {
// 		t.Errorf("Got error from good URL: %s", err.Error())
// 	}

// 	err = checkFromURL(ml, RevokedURL, false, false, false, "", "", crypto.SHA1)
// 	if err != nil {
// 		t.Errorf("Got error from valid URL with bad certificate: %s", err.Error())
// 	}

// 	err = checkFromURL(ml, BadURL, false, false, false, "", "", crypto.SHA1)
// 	if err == nil {
// 		t.Errorf("Should have gotten error from invalid URL")
// 	}
// }
