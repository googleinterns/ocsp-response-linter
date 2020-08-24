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

func LintProducedAtDate(resp *ocsp.Response) error {
	limit, err := time.ParseDuration(ProducedAtLimit)
	if err != nil {
		return err
	}
	if time.Since(resp.ProducedAt) > limit {
		return fmt.Errorf("OCSP Response producedAt date is more than %s in the past", ProducedAtLimit)
	}
	return nil
}

func LintThisUpdateDate(resp *ocsp.Response) error {
	limit, err := time.ParseDuration(ThisUpdateLimit)
	if err != nil {
		return err
	}
	if time.Since(resp.ThisUpdate) > limit {
		return fmt.Errorf("OCSP Response thisUpdate date is more than %s in the past", ThisUpdateLimit)
	}
	return nil
}
