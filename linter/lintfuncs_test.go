package linter

import (
    "github.com/googleinterns/ocsp-response-linter/ocsptools"
    "testing"
	"time"
)

const (
	RespBadDates = "../testdata/resps/oldfbresp"
)

// TestLintProducedAtDate tests LintProducedAtDate, which checks that an
// OCSP Response ProducedAt date is no more than ProducedAtLimit in the past
// Source: Apple Lint 03
func TestLintProducedAtDate(t *testing.T) {
    tools := ocsptools.Tools{}
    ocspResp, err := tools.ReadOCSPResp(RespBadDates)
    if err != nil {
        panic(err)
    }

    err = LintProducedAtDate(ocspResp)

    if err == nil {
    	t.Errorf("Should have had error: %s is more than %s in the past", ocspResp.ProducedAt.String(), ProducedAtLimit)
    }

    ocspResp.ProducedAt = time.Now()

    err = LintProducedAtDate(ocspResp)

    if err != nil {
    	t.Errorf("Should not have gotten error, instead got error: %s", err.Error())
    }
}

// TestLintThisUpdateDate tests LintThisUpdateDate, which checks that an 
// OCSP Response ThisUpdate date is no more than ThisUpdateLimit in the past
// Source: Apple Lint 03
func TestLintThisUpdateDate(t *testing.T) {
	tools := ocsptools.Tools{}
    ocspResp, err := tools.ReadOCSPResp(RespBadDates)
    if err != nil {
        panic(err)
    }

    err = LintThisUpdateDate(ocspResp)

    if err == nil {
    	t.Errorf("Should have had error: %s is more than %s in the past", ocspResp.ThisUpdate.String(), ThisUpdateLimit)
    }

    ocspResp.ThisUpdate = time.Now()

    err = LintThisUpdateDate(ocspResp)

    if err != nil {
    	t.Errorf("Should not have gotten error, instead got error: %s", err.Error())
    }
}
