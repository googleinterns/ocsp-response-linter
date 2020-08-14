package linter

import (
	"fmt"
	"golang.org/x/crypto/ocsp"
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
		"Check that response producedAt date is no more than four days in the past",
		"Apple Lint 03",
		LintProducedAtDate,
	},
	{
		"Check that response thisUpdate date is no more than four days in the past",
		"Apple Lint 03",
		LintThisUpdateDate,
	},
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
