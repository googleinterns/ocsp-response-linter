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

type lint struct {
	info   string
	source string
	exec   func(resp *ocsp.Response) error
}

type verification struct {
	info   string
	source string
	exec   func(resp *ocsp.Response) error
}

var lints = []lint{
	{
		"Check that response producedAt date is no more than four days in the past",
		"Apple Lint 03",
		lintProducedAtDate,
	},
	{
		"Check that response thisUpdate date is no more than four days in the past",
		"Apple Lint 03",
		lintThisUpdateDate,
	},
}

func lintProducedAtDate(resp *ocsp.Response) error {
	limit, err := time.ParseDuration(ProducedAtLimit)
	if err != nil {
		return err
	}
	if time.Since(resp.ProducedAt) > limit {
		return errors.New("OCSP Response producedAt date is more than 4 days in the past")
	}
	return nil
}

func lintThisUpdateDate(resp *ocsp.Response) error {
	limit, err := time.ParseDuration(ThisUpdateLimit)
	if err != nil {
		return err
	}
	if time.Since(resp.ThisUpdate) > limit {
		return errors.New("OCSP Response thisUpdate date is more than 4 days in the past")
	}
	return nil
}

func LintOCSPResp(resp *ocsp.Response) {
	fmt.Println("Linting OCSP Response...")
	for _, test := range lints {
		fmt.Print(test.info + ": ")
		err := test.exec(resp)
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
