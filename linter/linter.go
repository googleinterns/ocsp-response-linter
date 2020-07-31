package linter

import (
	"fmt"
	"golang.org/x/crypto/ocsp"
)

// check response for status and syntactic soundness
func Check_ocsp_resp(parsed_resp *ocsp.Response) {
	// TODO: Implement all the lint cases
	fmt.Println(ocsp.ResponseStatus(parsed_resp.Status).String()) // placeholder
}
