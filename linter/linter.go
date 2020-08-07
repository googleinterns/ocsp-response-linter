package linter

import (
	"fmt"
	"golang.org/x/crypto/ocsp"
	"time"
	"errors"
)

const (
	ProducedAtLimit = "96h" // 4 days
	ThisUpdateLimit = "96h" // 4 days
)

type lint struct {
	info string
	source string
	exec func(resp *ocsp.Response) error
}

type verification struct {
	info string
	source string
	exec func(resp *ocsp.Response) error
}

var lints = []lint{
	{
		"Check that response producedAt date is no more than four days in the past",
		"Apple Lint 03",
		lint_producedAtDate,
	},
	{
		"Check that response thisUpdate date is no more than four days in the past",
		"Apple Lint 03",
		lint_thisUpdateDate,
	},
}

func lint_producedAtDate(resp *ocsp.Response) error {
	limit, err := time.ParseDuration(ProducedAtLimit)
	if err != nil {
		return err
	}
	if time.Since(resp.ProducedAt) >  limit{
		return errors.New("OCSP Response producedAt date is more than 4 days in the past")
	}
	return nil
}

func lint_thisUpdateDate(resp *ocsp.Response) error {
	limit, err := time.ParseDuration(ThisUpdateLimit)
	if err != nil {
		return err
	}
	if time.Since(resp.ThisUpdate) > limit {
		return errors.New("OCSP Response thisUpdate date is more than 4 days in the past")
	}
	return nil
}

func Lint_OCSP_Resp(resp *ocsp.Response) {
	fmt.Println("Linting OCSP Response...")
	for _, test := range lints {
		fmt.Print(test.info + ": ")
		err := test.exec(resp)
		if err == nil {
			fmt.Println("passed")
		} else {
			fmt.Println("failed: " + err.Error())
		}
	}
	fmt.Println("Finished linting OCSP Response...")
}

// check response for status and syntactic soundness
func Check_Ocsp_Resp(resp *ocsp.Response) {
	// TODO: Implement all the lint cases
	Lint_OCSP_Resp(resp);

	fmt.Println(ocsp.ResponseStatus(resp.Status).String()) // placeholder
}
