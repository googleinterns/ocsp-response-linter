# Contributing

## Adding a New Lint

First write the function body of the lint in the `linter/lintfuncs.go` file, which should be of the form `func(resp *ocsp.Response) (LintStatus, string)`. `LintStatus` is an enum that takes the value `Passed`, `Failed`, or `Error`, which should indicate whether the lint passed, failed, or errored while running. The string returned should provide additional information on the status.

Example:

```go
// LintProducedAtDate checks that an OCSP Response ProducedAt date is no more than ProducedAtLimit in the past
// Source: Apple Lint 03
func LintProducedAtDate(resp *ocsp.Response) (LintStatus, string) {
	limit, err := time.ParseDuration(ProducedAtLimit)

	if err != nil {
		return Error, fmt.Sprintf("Could not parse time duration %s", ProducedAtLimit)
	}

	if time.Since(resp.ProducedAt) > limit {
		return Failed, fmt.Sprintf("OCSP Response producedAt date %s is more than %s in the past", resp.ProducedAt, ProducedAtLimit)
	}

	return Passed, fmt.Sprintf("OCSP Response producedAt date %s is within %s of the past", resp.ProducedAt, ProducedAtLimit)
}
```

Next please write unit tests for your new linting function in `linter/lintfuncs_test.go`

Example:

```go
// TestLintProducedAtDate tests LintProducedAtDate, which checks that an
// OCSP Response ProducedAt date is no more than ProducedAtLimit in the past
// Source: Apple Lint 03
func TestLintProducedAtDate(t *testing.T) {
	tools := ocsptools.Tools{}
	ocspResp, err := tools.ReadOCSPResp(RespBadDates)
	if err != nil {
		panic(err)
	}

	t.Run("Old ProducedAt date", func(t *testing.T) {
		status, _ := LintProducedAtDate(ocspResp)
		if status != Failed {
			t.Errorf("Should have had error: %s is more than %s in the past", ocspResp.ProducedAt.String(), ProducedAtLimit)
		}
	})

	ocspResp.ProducedAt = time.Now()

	t.Run("Happy path", func(t *testing.T) {
		status, info := LintProducedAtDate(ocspResp)
		if status != Passed {
			t.Errorf("Should not have gotten error, instead got error: %s", info)
		}
	})
}
```

Finally in `linter/linter.go`, add the address of a new `LintStruct` to the global array `Lints`. The `LintStruct` should contain a description of the lint (which will be printed to the console), the source of the lint, and the function name you just wrote in `linter/lintfuncs.go`.

Example:
```go
&LintStruct{
	fmt.Sprintf("Check that response producedAt date is no more than %s in the past", ProducedAtLimit),
	"Apple Lint 03",
	LintProducedAtDate,
}
```

