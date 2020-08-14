package linter

import (
	"errors"
	"fmt"
	"golang.org/x/crypto/ocsp"
	"time"
)

const (
	ProducedAtLimit = "96h" // 4 days
	ThisUpdateLimit = "96h" // 4 days
)

type lintstruct struct {
	info   string
	source string
	exec   func(resp *ocsp.Response) error
}

var Lints = []lintstruct{
	{
		"Check that response producedAt date is no more than " + ProducedAtLimit + " in the past",
		"Apple Lint 03",
		LintProducedAtDate,
	},
	{
		"Check that response thisUpdate date is no more than " + ThisUpdateLimit + " in the past",
		"Apple Lint 03",
		LintThisUpdateDate,
	},
}

func LintProducedAtDate(resp *ocsp.Response) error {
	limit, err := time.ParseDuration(ProducedAtLimit)
	if err != nil {
		return err
	}
  
	if time.Since(resp.ProducedAt) >  limit {
		return errors.New("OCSP Response producedAt date is more than " + ProducedAtLimit + " in the past")
	}
	return nil
}

func LintThisUpdateDate(resp *ocsp.Response) error {
	limit, err := time.ParseDuration(ThisUpdateLimit)
	if err != nil {
		return err
	}
	if time.Since(resp.ThisUpdate) > limit {
		return errors.New("OCSP Response thisUpdate date is more than " + ThisUpdateLimit + " in the past")
	}
	return nil
}

func LintOCSPResp(resp *ocsp.Response) {
	fmt.Println("Linting OCSP Response...")
	for _, lint := range Lints {
		fmt.Print(lint.info + ": ")
		err := lint.exec(resp)
		if err == nil {
			fmt.Println("passed")
		} else {
			fmt.Println("failed: " + err.Error())
		}
	}
	fmt.Println("Finished linting OCSP Response...")
}

// check response for status and syntactic soundness
func CheckOCSPResp(resp *ocsp.Response) {
	// TODO: Implement all the lint cases
	LintOCSPResp(resp)

	fmt.Println(ocsp.ResponseStatus(resp.Status).String()) // placeholder
}
