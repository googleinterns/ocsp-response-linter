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
// OCSP Response ThisUpdate date is no more than ThisUpdateLimit in the past
// Source: Apple Lint 03
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
