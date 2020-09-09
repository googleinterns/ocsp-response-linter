package linter

//go:generate mockgen -source=linter.go -destination=../mocks/lintermock/mock_linter.go -package=lintermock

import (
	"fmt"
	"golang.org/x/crypto/ocsp"
	"sort"
)

var StatusIntMap = map[int]string{
	ocsp.Good:    "good",
	ocsp.Revoked: "revoked",
	ocsp.Unknown: "unknown",
	// ocsp.SeverFailed is never used: godoc.org/golang.org/x/crypto/ocsp#pkg-constants
}

type LintStruct struct {
	Info   string                          // description of the lint
	Source string                          // source of the lint
	Exec   func(resp *ocsp.Response) (LintStatus, string) // the linting function itself
}

// Lints is the global array of lints that are to be tested (TODO: change to a map)
var Lints = []*LintStruct{
	&LintStruct{
		"Check that response producedAt date is no more than " + ProducedAtLimit + " in the past",
		"Apple Lint 03",
		LintProducedAtDate,
	},
	&LintStruct{
		"Check that response thisUpdate date is no more than " + ThisUpdateLimit + " in the past",
		"Apple Lint 03",
		LintThisUpdateDate,
	},
}

type LintStatus string

const (
	Passed LintStatus = "PASSED" // lint passed
	Failed LintStatus = "FAILED" // lint failed
	Error LintStatus = "ERROR" // encountered error while running lint
)

type LintResult struct {
	Lint *LintStruct
	Status LintStatus
	Info string
}

type LinterInterface interface {
	LintOCSPResp(*ocsp.Response, bool)
}

type Linter struct{}

// printResults prints the results of all the lints run
func printResults(results []*LintResult, verbose bool) {
	fmt.Println("Printing lint results: ")
	// sort by status so printing prints all the lints that errored, then failed, then passed
	sort.Slice(results, func(i, j int) bool {
		return results[i].Status < results[j].Status
	})

	allPassed := true

	for _, result := range results {
		if result.Status != Passed {
			allPassed = false
		}
		if result.Status != Passed || verbose {
			fmt.Printf("%s: %s: %s \n", result.Lint.Info, result.Status, result.Info)
		}
	}

	if allPassed {
		fmt.Println("OCSP Response passed all lints")
	}
}

// LintOCSPResp takes in a parsed OCSP response and prints its status, and then lints it
func (l Linter) LintOCSPResp(resp *ocsp.Response, verbose bool) {
	fmt.Printf("OCSP Response status: %s \n\n", StatusIntMap[resp.Status])

	var results []*LintResult
	for _, lint := range Lints {
		status, info := lint.Exec(resp)
		results = append(results, &LintResult{
			Lint: lint,
			Status: status,
			Info: info,
		})
	}

	printResults(results, verbose)
}
