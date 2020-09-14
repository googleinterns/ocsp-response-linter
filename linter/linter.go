package linter

//go:generate mockgen -source=linter.go -destination=../mocks/lintermock/mock_linter.go -package=lintermock

import (
	"crypto/x509"
	"fmt"
	"golang.org/x/crypto/ocsp"
	"sort"
)

// StatusIntMap maps ocsp statuses to strings
var StatusIntMap = map[int]string{
	ocsp.Good:    "good",
	ocsp.Revoked: "revoked",
	ocsp.Unknown: "unknown",
	// ocsp.SeverFailed is never used: godoc.org/golang.org/x/crypto/ocsp#pkg-constants
}

// LintStruct defines the struct of a lint
type LintStruct struct {
	Info   string                          // description of the lint
	Source string                          // source of the lint
	Exec   func(resp *ocsp.Response, leafCert *x509.Certificate) (LintStatus, string) // the linting function itself
}

// Lints is the global array of lints that are to be tested (TODO: change to a map)
var Lints = []*LintStruct{
	&LintStruct{
		"Check response signature",
		"Apple Lints 10 & 12",
		CheckSignature,
	},
	&LintStruct{
		"Check response producedAt date",
		"Apple Lints 03 & 05",
		LintProducedAtDate,
	},
	&LintStruct{
		"Check response thisUpdate date",
		"Apple Lints 03 & 05",
		LintThisUpdateDate,
	},
	&LintStruct{
		"Check response nextUpdate date",
		"Apple Lint 04",
		LintNextUpdateDate,
	},
}

// LintStatus defines the possible statuses for a lint
type LintStatus string

const (
	Passed LintStatus = "PASSED" // lint passed
	Failed LintStatus = "FAILED" // lint failed
	Error LintStatus = "ERROR" // encountered error while running lint
)

// LintResult defines the struct of the result of a Lint
type LintResult struct {
	Lint *LintStruct
	Status LintStatus
	Info string
}

// LinterInterface is an interface containing the functions that are exported from this file
type LinterInterface interface {
	LintOCSPResp(*ocsp.Response, *x509.Certificate, bool)
}

// Linter is a struct of type LinterInterface
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
func (l Linter) LintOCSPResp(resp *ocsp.Response, leafCert *x509.Certificate, verbose bool) {
	fmt.Printf("OCSP Response status: %s \n\n", StatusIntMap[resp.Status])

	var results []*LintResult
	for _, lint := range Lints {
		status, info := lint.Exec(resp, leafCert)
		results = append(results, &LintResult{
			Lint: lint,
			Status: status,
			Info: info,
		})
	}

	printResults(results, verbose)
}
