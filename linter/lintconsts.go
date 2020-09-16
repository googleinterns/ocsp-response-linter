package linter

import (
	"golang.org/x/crypto/ocsp"
)

type CertType string
const (
	Subscriber CertType = "Subscriber"
	CA CertType = "CA"
)

type OCSPStatus string
const (
	Good OCSPStatus = "Good"
	Revoked OCSPStatus = "Revoked"
	None OCSPStatus = ""
)

type LintOpts struct {
	LeafCertType CertType
	LeafCertNonIssued bool
	ExpectedStatus OCSPStatus
}

// LintStatus defines the possible statuses for a lint
type LintStatus string

const (
	Passed LintStatus = "PASSED" // lint passed
	Failed LintStatus = "FAILED" // lint failed
	Unknown LintStatus = "UNKNOWN" // unknown whether lint passed or failed
	Error  LintStatus = "ERROR"  // encountered error while running lint
)

// LintResult defines the struct of the result of a Lint
type LintResult struct {
	Lint   *LintStruct
	Status LintStatus
	Info   string
}

// StatusIntMap maps ocsp statuses to strings
var StatusIntMap = map[int]string{
	ocsp.Good:    "good",
	ocsp.Revoked: "revoked",
	ocsp.Unknown: "unknown",
	// ocsp.SeverFailed is never used: godoc.org/golang.org/x/crypto/ocsp#pkg-constants
}