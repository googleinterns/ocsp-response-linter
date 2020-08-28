package main

import (
	"crypto"
	"io/ioutil"
	"log"
	"os"
	"testing"
)

const (
	GoodResp = "./testdata/resps/oldfbresp"
	GoodCert = "./testdata/certs/google.der"
	ExpiredCert = "./testdata/certs/expiredcert.der"
	NoIssuingURLCert = "./testdata/certs/rootcert.der"
	GoodURL = "google.com:443"
	RevokedURL = "revoked.grc.com:443"
	BadURL = "blah.blah.blah"
)

// TestMain sets up the testing framework
func TestMain(m *testing.M) {
	// discard logging
	log.SetOutput(ioutil.Discard)
	os.Exit(m.Run())
}

// TestCheckFromFile tests checkFromFile
func TestCheckFromFile(t *testing.T) {
	err := checkFromFile(GoodResp)
	if err != nil {
		t.Errorf("Got error reading good response: %s", err.Error())
	}

	err = checkFromFile(GoodCert)
	if err == nil {
		t.Errorf("Should have gotten error reading file that is not an OCSP response")
	}
}

// TestCheckFromFile tests checkFromFile
func TestCheckFromCert(t *testing.T) {
	err := checkFromCert(GoodCert, false, "", "", crypto.SHA1)
	if err != nil {
		t.Errorf("Got error reading good certificate file: %s", err.Error())
	}

	err = checkFromCert(GoodResp, false, "", "", crypto.SHA1)
	if err == nil {
		t.Errorf("Should have gotten error reading file that is not a certificate")
	}

	err = checkFromCert(NoIssuingURLCert, false, "", "", crypto.SHA1)
	if err == nil {
		t.Errorf("Should have gotten no issuing certificate url field error")
	}

	err = checkFromCert(ExpiredCert, false, "", "", crypto.SHA1)
	if err == nil {
		t.Errorf("Should have gotten unauthorized error fetching the OCSP response")
	}
}

// TestCheckFromURL tests checkFromURL
func TestCheckFromURL(t *testing.T) {
	err := checkFromURL(GoodURL, false, false, false, "", "", crypto.SHA1)
	if err != nil {
		t.Errorf("Got error from good URL: %s", err.Error())
	}

	err = checkFromURL(RevokedURL, false, false, false, "", "", crypto.SHA1)
	if err != nil {
		t.Errorf("Got error from valid URL with bad certificate: %s", err.Error())
	}

	err = checkFromURL(BadURL, false, false, false, "", "", crypto.SHA1)
	if err == nil {
		t.Errorf("Should have gotten error from invalid URL")
	}
}
