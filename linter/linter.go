package linter

//go:generate mockgen -source=linter.go -destination=../mocks/lintermock/mock_linter.go -package=lintermock

import (
	"crypto/x509"
	"fmt"
	"golang.org/x/crypto/ocsp"
	"sort"
)

// LintStruct defines the struct of a lint
type LintStruct struct {
	Info   string                                                                     // description of the lint
	Source string                                                                     // source of the lint
	Exec   func(resp *ocsp.Response, issuerCert *x509.Certificate, lintOpts *LintOpts) (LintStatus, string) // the linting function itself
}

// Lints is the global array of lints that are to be tested (TODO: change to a map)
var Lints = []*LintStruct{
	{
		"Check response signature",
		"Apple Lints 10 & 12",
		CheckSignature,
	},
	{
		"Check OCSP responder",
		"Apple Lint 13",
		CheckResponder,
	},
	{
		"Check response producedAt date",
		"Apple Lints 03 & 05",
		LintProducedAtDate,
	},
	{
		"Check response thisUpdate date",
		"Apple Lints 03 & 05",
		LintThisUpdateDate,
	},
	{
		"Check response nextUpdate date",
		"Apple Lint 04",
		LintNextUpdateDate,
	},
}

// LinterInterface is an interface containing the functions that are exported from this file
type LinterInterface interface {
	LintOCSPResp(*ocsp.Response, *x509.Certificate, *LintOpts, bool)
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
func (l Linter) LintOCSPResp(resp *ocsp.Response, issuerCert *x509.Certificate, lintOpts *LintOpts, verbose bool) {
	fmt.Printf("OCSP Response status: %s \n\n", StatusIntMap[resp.Status])

	var results []*LintResult
	for _, lint := range Lints {
		status, info := lint.Exec(resp, issuerCert, lintOpts)
		results = append(results, &LintResult{
			Lint:   lint,
			Status: status,
			Info:   info,
		})
	}

	printResults(results, verbose)
}
