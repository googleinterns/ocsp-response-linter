package linter

import (
	"crypto/x509"
	"github.com/googleinterns/ocsp-response-linter/ocsptools"
	"testing"
	"time"
)

const (
	RespBadDates = "../testdata/resps/oldfbresp"
)

// TestCheckSignature tests CheckSignature, which checks that an
// OCSP Response signature is present and not signed with an algorithm
// that uses SHA-1
// Source: Apple Lint 10
func TestCheckSignature(t *testing.T) {
	tools := ocsptools.Tools{}
	ocspResp, err := tools.ReadOCSPResp(RespBadDates)
	if err != nil {
		panic(err)
	}

	t.Run("Happy Path", func(t *testing.T) {
		status, info := CheckSignature(ocspResp, nil)
		if status != Passed {
			t.Errorf("Lint should have passed, instead got status %s: %s", status, info)
		}
	})

	ocspResp.SignatureAlgorithm = x509.SHA1WithRSA
	t.Run("SHA1 signature algorithm", func(t *testing.T) {
		status, info := CheckSignature(ocspResp, nil)
		if status != Failed {
			t.Errorf("Lint should have failed, instead got status %s: %s", status, info)
		}
	})

	ocspResp.Signature = nil
	t.Run("No signature", func(t *testing.T) {
		status, info := CheckSignature(ocspResp, nil)
		if status != Failed {
			t.Errorf("Lint should have failed, instead got status %s: %s", status, info)
		}
	})
}

// TestLintProducedAtDate tests LintProducedAtDate, which checks that an
// OCSP Response ProducedAt date is not too far in the past
// Source: Apple Lints 03 & 05
func TestLintProducedAtDate(t *testing.T) {
	tools := ocsptools.Tools{}
	ocspResp, err := tools.ReadOCSPResp(RespBadDates)
	if err != nil {
		panic(err)
	}

	t.Run("Old ProducedAt date", func(t *testing.T) {
		status, info := LintProducedAtDate(ocspResp, nil)
		if status != Failed {
			t.Errorf("Lint should have failed, instead got status %s: %s", status, info)
		}
	})

	ocspResp.ProducedAt = time.Now()

	t.Run("Happy path", func(t *testing.T) {
		status, info := LintProducedAtDate(ocspResp, nil)
		if status != Passed {
			t.Errorf("Lint should have passed, instead got status %s: %s", status, info)
		}
	})
}

// TestLintThisUpdateDate tests LintThisUpdateDate, which checks that an
// OCSP Response ThisUpdate date is not too far in the past
// Source: Apple Lints 03 & 05
func TestLintThisUpdateDate(t *testing.T) {
	tools := ocsptools.Tools{}
	ocspResp, err := tools.ReadOCSPResp(RespBadDates)
	if err != nil {
		panic(err)
	}

	t.Run("Old ThisUpdate date", func(t *testing.T) {
		status, info := LintThisUpdateDate(ocspResp, nil)
		if status != Failed {
			t.Errorf("Lint should have failed, instead got status %s: %s", status, info)
		}
	})

	ocspResp.ThisUpdate = time.Now()

	t.Run("Happy path", func(t *testing.T) {
		status, info := LintThisUpdateDate(ocspResp, nil)
		if status != Passed {
			t.Errorf("Lint should have passed, instead got status %s: %s", status, info)
		}
	})
}

// TestLintNextUpdateDate tests LintNextUpdateDate, which checks that an OCSP Response
// NextUpdate date is no more than NextUpdateLimit in the future of its ThisUpdate date
// Source: Apple Lint 04
func TestLintNextUpdateDate(t *testing.T) {
	tools := ocsptools.Tools{}
	ocspResp, err := tools.ReadOCSPResp(RespBadDates)
	if err != nil {
		panic(err)
	}

	t.Run("Happy path", func(t *testing.T) {
		status, info := LintNextUpdateDate(ocspResp, nil)
		if status != Passed {
			t.Errorf("Lint should have passed, instead got status %s: %s", status, info)
		}
	})

	ocspResp.NextUpdate = time.Now()
	t.Run("NextUpdate date too far in the future", func(t *testing.T) {
		status, info := LintNextUpdateDate(ocspResp, nil)
		if status != Failed {
			t.Errorf("Lint should have failed, instead got status %s: %s", status, info)
		}
	})	
}
