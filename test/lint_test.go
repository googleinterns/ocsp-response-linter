package test

import (
	"testing"
	"golang.org/x/crypto/ocsp"
	"io/ioutil"
	"../linter"
	"fmt"
	"time"
)

const (
	TestRespDates = "./test-resps/oldfbresp"
)


func TestLintProducedAtDate(t *testing.T) {
	ocsp_resp, err := ioutil.ReadFile(TestRespDates)
	if err != nil {
		panic("Error reading file: " + err.Error())
	}
	parsed_resp, err := ocsp.ParseResponse(ocsp_resp, nil)
	if err != nil {
    	fmt.Println(string(ocsp_resp))
        panic(err.Error())
    }

    err = linter.LintProducedAtDate(parsed_resp)

    if err == nil {
    	t.Errorf("Should have had error: %s is more than %s in the past", parsed_resp.ProducedAt.String(), linter.ProducedAtLimit)
    }

    parsed_resp.ProducedAt = time.Now()

    err = linter.LintProducedAtDate(parsed_resp)

    if err != nil {
    	t.Errorf("Should not have gotten error, instead got error: %s", err.Error())
    }
}

func TestLintThisUpdateDate(t *testing.T) {
	ocsp_resp, err := ioutil.ReadFile(TestRespDates)
	if err != nil {
		panic("Error reading file: " + err.Error())
	}
	parsed_resp, err := ocsp.ParseResponse(ocsp_resp, nil)
	if err != nil {
    	fmt.Println(string(ocsp_resp))
        panic(err.Error())
    }

    err = linter.LintThisUpdateDate(parsed_resp)

    if err == nil {
    	t.Errorf("Should have had error: %s is more than %s in the past", parsed_resp.ThisUpdate.String(), linter.ThisUpdateLimit)
    }

    parsed_resp.ThisUpdate = time.Now()

    err = linter.LintThisUpdateDate(parsed_resp)

    if err != nil {
    	t.Errorf("Should not have gotten error, instead got error: %s", err.Error())
    }
}
