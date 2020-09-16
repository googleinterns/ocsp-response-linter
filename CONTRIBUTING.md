# Contributing

## Adding a New Lint

First write the function body of the lint in the `linter/lintfuncs.go` file, which should be of the form `func(resp *ocsp.Response, leafCert *x509.Certificate, issuerCert *x509.Certificate, lintOpts *LintOpts) (LintStatus, string)`. `LintStatus` is an enum that takes the value `Passed`, `Failed`, or `Error`, which should indicate whether the lint passed, failed, or errored while running. The string returned should provide additional information on the status.

Example:

```go
// CheckStatus checks that the status of the OCSP response matches what the user expects it to be
// Source: Apple Lint 07
func CheckStatus(resp *ocsp.Response, leafCert *x509.Certificate, issuerCert *x509.Certificate, lintOpts *LintOpts) (LintStatus, string) {
	if lintOpts.ExpectedStatus == None {
		return Passed, fmt.Sprintf("User did not specify an expected status (fyi OCSP response status was %s)", StatusIntMap[resp.Status])
	} 

	expectedStatus := ocsp.Good
	if lintOpts.ExpectedStatus == Revoked {
		expectedStatus = ocsp.Revoked
	}

	if resp.Status != expectedStatus {
		return Failed, fmt.Sprintf("Expected status %s, OCSP response status was %s", lintOpts.ExpectedStatus, StatusIntMap[resp.Status])
	}

	return Passed, fmt.Sprintf("OCSP Response status matched expected status of %s", lintOpts.ExpectedStatus)
}
```

Next please write unit tests for your new linting function in `linter/lintfuncs_test.go`

Example:

```go
// TestCheckStatus tests CheckStatus, which checks whether or not the OCSP response
// status matches what the user expected
// Source: Apple Lint 07
func TestCheckStatus(t *testing.T) {
	mockLintOpts := &LintOpts{
		LeafCertType: Subscriber,
		LeafCertNonIssued: false,
		ExpectedStatus: None,
	}

	ocspResp, err := ocsptools.Tools{}.ReadOCSPResp(RespBadDates)
	if err != nil {
		panic(fmt.Sprintf("Could not read OCSP Response file %s: %s", RespBadDates, err))
	}

	t.Run("No expected status", func(t *testing.T) {
		status, info := CheckStatus(ocspResp, nil, nil, mockLintOpts)
		if status != Passed {
			t.Errorf("Lint should have passed, instead got status %s: %s", status, info)
		}
	})

	mockLintOpts.ExpectedStatus = Revoked
	t.Run("Expected status revoked for good response", func(t *testing.T) {
		status, info := CheckStatus(ocspResp, nil, nil, mockLintOpts)
		if status != Failed {
			t.Errorf("Lint should have failed, instead got status %s: %s", status, info)
		}
	})

	mockLintOpts.ExpectedStatus = Good
	t.Run("Expected status good for good response", func(t *testing.T) {
		status, info := CheckStatus(ocspResp, nil, nil, mockLintOpts)
		if status != Passed {
			t.Errorf("Lint should have passed, instead got status %s: %s", status, info)
		}
	})
}
```

Finally in `linter/linter.go`, add the address of a new `LintStruct` to the global array `Lints`. The `LintStruct` should contain a description of the lint (which will be printed to the console), the source of the lint, and the function name you just wrote in `linter/lintfuncs.go`.

Example:
```go
{
	"Check response status",
	"Apple Lint 07",
	CheckStatus,
}
```

