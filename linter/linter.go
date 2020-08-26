package linter

import (
	"fmt"
	"golang.org/x/crypto/ocsp"
)

var StatusIntMap = map[int]string {
	ocsp.Good: "good",
	ocsp.Revoked: "revoked",
	ocsp.Unknown: "unknown",
	// ocsp.SeverFailed is never used
}

type LintStruct struct {
	info   string // description of the lint
	source string // source of the lint
	exec   func(resp *ocsp.Response) error // the linting function itself
}

// Lints is the global array of lints that are to be tested (TODO: change to a map)
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

// LintOCSPResp takes in a parsed OCSP response and prints its status
// TODO: change function so that it returns a list of failed lints
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
	fmt.Println("Finished linting OCSP response")
}
