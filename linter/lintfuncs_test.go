package linter

import (
	"crypto/x509"
	"fmt"
	"github.com/googleinterns/ocsp-response-linter/ocsptools"
	"golang.org/x/crypto/ocsp"
	"testing"
	"time"
)

const (
	RespBadDates = "../testdata/resps/oldfbresp" // basic OCSP response
	GoogleResp = "../testdata/resps/googleresp"
	GoogleIssuerCert = "../testdata/certs/googleissuer.der"
)

// TestCheckSignature tests CheckSignature, which checks that an OCSP Response
// signature is present and not signed with an algorithm that uses SHA-1
// Source: Apple Lints 10 & 12
func TestCheckSignature(t *testing.T) {
	mockLintOpts := &LintOpts{
		LeafCertType: Subscriber,
		LeafCertNonIssued: false,
		ExpectedStatus: None,
	}

	ocspResp, err := ocsptools.Tools{}.ReadOCSPResp(RespBadDates)
	if err != nil {
		panic(fmt.Sprintf("Could not read OCSP Response file %s: %s", RespBadDates, err))
	}

	t.Run("Happy Path", func(t *testing.T) {
		status, info := CheckSignature(ocspResp, nil, mockLintOpts)
		if status != Passed {
			t.Errorf("Lint should have passed, instead got status %s: %s", status, info)
		}
	})

	ocspResp.SignatureAlgorithm = x509.SHA1WithRSA
	t.Run("SHA1 signature algorithm", func(t *testing.T) {
		status, info := CheckSignature(ocspResp, nil, mockLintOpts)
		if status != Failed {
			t.Errorf("Lint should have failed, instead got status %s: %s", status, info)
		}
	})

	ocspResp.Signature = nil
	t.Run("No signature", func(t *testing.T) {
		status, info := CheckSignature(ocspResp, nil, mockLintOpts)
		if status != Failed {
			t.Errorf("Lint should have failed, instead got status %s: %s", status, info)
		}
	})
}

// TestCheckResponder tests CheckResponder, which checks that the OCSP responder
// is either the issuing CA or a delegated responder issued by the issuing CA
// Source: Apple Lint 13
func TestCheckResponder(t *testing.T) {
	mockLintOpts := &LintOpts{
		LeafCertType: Subscriber,
		LeafCertNonIssued: false,
		ExpectedStatus: None,
	}

	ocspResp, err := ocsptools.Tools{}.ReadOCSPResp(GoogleResp)
	if err != nil {
		panic(fmt.Sprintf("Could not read OCSP Response file %s: %s", GoogleResp, err))
	}

	issuerCert, err := ocsptools.Tools{}.ParseCertificateFile(GoogleIssuerCert)
	if err != nil {
		panic(fmt.Sprintf("Could not read issuer certificate file %s: %s", GoogleIssuerCert, err))
	}

	t.Run("OCSP Responder is Issuer CA, check public keys", func (t *testing.T) {
		status, info := CheckResponder(ocspResp, issuerCert, mockLintOpts)
		if status != Passed {
			t.Errorf("Lint should have passed, instead got status %s: %s", status, info)
		}
	})

	ocspResp.RawResponderName = []byte{1}
	issuerCert.RawSubject = []byte{1}

	t.Run("OCSP Responder is Issuer CA, check names", func (t *testing.T) {
		status, info := CheckResponder(ocspResp, issuerCert, mockLintOpts)
		if status != Passed {
			t.Errorf("Lint should have passed, instead got status %s: %s", status, info)
		}
	})

	badResp, err := ocsptools.Tools{}.ReadOCSPResp(RespBadDates)
	if err != nil {
		panic(fmt.Sprintf("Could not read OCSP Response file %s: %s", RespBadDates, err))
	}

	t.Run("No certificate in delegate responder's OCSP response", func(t *testing.T) {
		status, info := CheckResponder(badResp, issuerCert, mockLintOpts)
		if status != Failed {
			t.Errorf("Lint should have failed, instead got status %s: %s", status, info)
		}
	})
}

// TestLintProducedAtDate tests LintProducedAtDate, which checks that an
// OCSP Response ProducedAt date is not too far in the past
// Source: Apple Lints 03 & 05
func TestLintProducedAtDate(t *testing.T) {
	mockLintOpts := &LintOpts{
		LeafCertType: Subscriber,
		LeafCertNonIssued: false,
		ExpectedStatus: None,
	}

	ocspResp, err := ocsptools.Tools{}.ReadOCSPResp(RespBadDates)
	if err != nil {
		panic(fmt.Sprintf("Could not read OCSP Response file %s: %s", RespBadDates, err))
	}

	t.Run("Old ProducedAt date", func(t *testing.T) {
		status, info := LintProducedAtDate(ocspResp, nil, mockLintOpts)
		if status != Failed {
			t.Errorf("Lint should have failed, instead got status %s: %s", status, info)
		}
	})

	ocspResp.ProducedAt = time.Now()

	t.Run("Happy path", func(t *testing.T) {
		status, info := LintProducedAtDate(ocspResp, nil, mockLintOpts)
		if status != Passed {
			t.Errorf("Lint should have passed, instead got status %s: %s", status, info)
		}
	})
}

// TestLintThisUpdateDate tests LintThisUpdateDate, which checks that an
// OCSP Response ThisUpdate date is not too far in the past
// Source: Apple Lints 03 & 05
func TestLintThisUpdateDate(t *testing.T) {
	mockLintOpts := &LintOpts{
		LeafCertType: Subscriber,
		LeafCertNonIssued: false,
		ExpectedStatus: None,
	}

	ocspResp, err := ocsptools.Tools{}.ReadOCSPResp(RespBadDates)
	if err != nil {
		panic(fmt.Sprintf("Could not read OCSP Response file %s: %s", RespBadDates, err))
	}

	t.Run("Old ThisUpdate date", func(t *testing.T) {
		status, info := LintThisUpdateDate(ocspResp, nil, mockLintOpts)
		if status != Failed {
			t.Errorf("Lint should have failed, instead got status %s: %s", status, info)
		}
	})

	ocspResp.ThisUpdate = time.Now()

	t.Run("Happy path", func(t *testing.T) {
		status, info := LintThisUpdateDate(ocspResp, nil, mockLintOpts)
		if status != Passed {
			t.Errorf("Lint should have passed, instead got status %s: %s", status, info)
		}
	})
}

// TestLintNextUpdateDate tests LintNextUpdateDate, which checks that an OCSP Response
// NextUpdate date is no more than NextUpdateLimit in the future of its ThisUpdate date
// Source: Apple Lint 04
func TestLintNextUpdateDate(t *testing.T) {
	mockLintOpts := &LintOpts{
		LeafCertType: Subscriber,
		LeafCertNonIssued: false,
		ExpectedStatus: None,
	}

	ocspResp, err := ocsptools.Tools{}.ReadOCSPResp(RespBadDates)
	if err != nil {
		panic(fmt.Sprintf("Could not read OCSP Response file %s: %s", RespBadDates, err))
	}

	t.Run("Happy path", func(t *testing.T) {
		status, info := LintNextUpdateDate(ocspResp, nil, mockLintOpts)
		if status != Passed {
			t.Errorf("Lint should have passed, instead got status %s: %s", status, info)
		}
	})

	ocspResp.NextUpdate = time.Now()
	t.Run("NextUpdate date too far in the future", func(t *testing.T) {
		status, info := LintNextUpdateDate(ocspResp, nil, mockLintOpts)
		if status != Failed {
			t.Errorf("Lint should have failed, instead got status %s: %s", status, info)
		}
	})
}

// TestLintStatusForNonIssuedCert tests LintStatusForNonIssuedCert, which checks that an
// OCSP Response for a non issued certificate has a status that is not Good
// Source: Apple Lint 06
func TestLintStatusForNonIssuedCert(t *testing.T) {
	mockLintOpts := &LintOpts{
		LeafCertType: Subscriber,
		LeafCertNonIssued: false,
		ExpectedStatus: None,
	}

	ocspResp, err := ocsptools.Tools{}.ReadOCSPResp(RespBadDates)
	if err != nil {
		panic(fmt.Sprintf("Could not read OCSP Response file %s: %s", RespBadDates, err))
	}

	t.Run("Issued Certificate", func(t *testing.T) {
		status, info := LintStatusForNonIssuedCert(ocspResp, nil, mockLintOpts)
		if status != Passed {
			t.Errorf("Lint should have passed, instead got status %s: %s", status, info)
		}
	})

	mockLintOpts.LeafCertNonIssued = true
	t.Run("Non issued certificate with status good", func(t *testing.T) {
		status, info := LintStatusForNonIssuedCert(ocspResp, nil, mockLintOpts)
		if status != Failed {
			t.Errorf("Lint should have failed, instead got status %s: %s", status, info)
		}
	})

	ocspResp.Status = ocsp.Revoked
	t.Run("Non issued certificate with status revoked", func(t *testing.T) {
		status, info := LintStatusForNonIssuedCert(ocspResp, nil, mockLintOpts)
		if status != Passed {
			t.Errorf("Lint should have passed, instead got status %s: %s", status, info)
		}
	})
}
