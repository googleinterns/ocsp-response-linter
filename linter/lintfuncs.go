package linter

import (
	"fmt"
	"golang.org/x/crypto/ocsp"
	"time"
)

const (
	ProducedAtLimit = "96h" // 4 days
	ThisUpdateLimit = "96h" // 4 days
)

// LintProducedAtDate checks that an OCSP Response ProducedAt date is no more than ProducedAtLimit in the past
// Source: Apple Lint 03
func LintProducedAtDate(resp *ocsp.Response) (LintStatus, string) {
	limit, err := time.ParseDuration(ProducedAtLimit)

	if err != nil {
		return Error, fmt.Sprintf("Could not parse time duration %s", ProducedAtLimit)
	}

	if time.Since(resp.ProducedAt) > limit {
		return Failed, fmt.Sprintf("OCSP Response producedAt date %s is more than %s in the past", resp.ProducedAt, ProducedAtLimit)
	}

	return Passed, fmt.Sprintf("OCSP Response producedAt date %s is within %s of the past", resp.ProducedAt, ProducedAtLimit)
}

// LintThisUpdateDate checks that an OCSP Response ThisUpdate date is no more than ThisUpdateLimit in the past
// Source: Apple Lint 03
func LintThisUpdateDate(resp *ocsp.Response) (LintStatus, string) {
	limit, err := time.ParseDuration(ThisUpdateLimit)
	if err != nil {
		return Error, fmt.Sprintf("Could not parse time duration %s", ThisUpdateLimit)
	}

	if time.Since(resp.ThisUpdate) > limit {
		return Failed, fmt.Sprintf("OCSP Response thisUpdate date %s is more than %s in the past", resp.ThisUpdate, ThisUpdateLimit)
		
	}

	return Passed, fmt.Sprintf("OCSP Response thisUpdate date %s is within %s of the past", resp.ThisUpdate, ThisUpdateLimit)
	
}
