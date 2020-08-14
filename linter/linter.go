package linter

import (
	"fmt"
	"golang.org/x/crypto/ocsp"
)

const (
	ProducedAtLimit = "96h" // 4 days
	ThisUpdateLimit = "96h" // 4 days
)

type LintStruct struct {
	info   string
	source string
	exec   func(resp *ocsp.Response) error
}

var StatusIntMap = map[int]string {
	ocsp.Good: "good",
	ocsp.Revoked: "revoked",
	ocsp.Unknown: "unknown",
	// ocsp.SeverFailed is never used:
}

var Lints = []LintStruct{
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
	fmt.Println("OCSP Response status: " + StatusIntMap[resp.Status]) // placeholder

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
	fmt.Println("Finished linting OCSP response...")
}
