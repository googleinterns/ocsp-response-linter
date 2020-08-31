package linter

//go:generate mockgen -source=linter.go -destination=../mocks/mock_linter.go -package=mocks

import (
	"log"
	"golang.org/x/crypto/ocsp"
)

var StatusIntMap = map[int]string {
	ocsp.Good: "good",
	ocsp.Revoked: "revoked",
	ocsp.Unknown: "unknown",
	// ocsp.SeverFailed is never used: godoc.org/golang.org/x/crypto/ocsp#pkg-constants
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

type LinterInterface interface {
	LintOCSPResp(*ocsp.Response)
}

type Linter struct{}

// LintOCSPResp takes in a parsed OCSP response and prints its status
// TODO: change function so that it returns a list of failed lints
func (l Linter) LintOCSPResp(resp *ocsp.Response) {
	log.Println("OCSP Response status: " + StatusIntMap[resp.Status]) // placeholder

	log.Println("Linting OCSP Response...")
	for _, lint := range Lints {
		log.Print(lint.info + ": ")
		err := lint.exec(resp)
		if err == nil {
			log.Println("passed")
		} else {
			log.Println("failed: " + err.Error())
		}
	}
	log.Println("Finished linting OCSP response")
}
