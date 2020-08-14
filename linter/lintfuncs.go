package linter

import (
	"errors"
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
		return errors.New("OCSP Response producedAt date is more than 4 days in the past")
	}
	return nil
}

func LintThisUpdateDate(resp *ocsp.Response) error {
	limit, err := time.ParseDuration(ThisUpdateLimit)
	if err != nil {
		return err
	}
	if time.Since(resp.ThisUpdate) > limit {
		return errors.New("OCSP Response thisUpdate date is more than 4 days in the past")
	}
	return nil
}
