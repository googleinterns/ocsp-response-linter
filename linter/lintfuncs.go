package linter

import (
	"crypto/x509"
	"fmt"
	"golang.org/x/crypto/ocsp"
	"time"
)

const (
	ProducedAtLimitSubscriber = "96h" // 4 days
	ThisUpdateLimitSubscriber = "96h" // 4 days
	ProducedAtLimitCA = "8760h" // 365 days
	ThisUpdateLimitCA = "8760h" // 365 days
)

var DurationToString = map[string]string {
	ProducedAtLimitSubscriber: "4 days",
	ProducedAtLimitCA: "365 days",
}

// CheckSignature checks in the ocsp response is signed with an algorithm that uses SHA1
// Source: Apple Lint 10
func CheckSignature(resp *ocsp.Response, leafCert *x509.Certificate) (LintStatus, string) {
	if resp.Signature == nil || len(resp.Signature) == 0 {
		return Failed, "OCSP Response is not signed"
	}

	algo := resp.SignatureAlgorithm

	if algo == x509.SHA1WithRSA || algo == x509.DSAWithSHA1 || algo == x509.ECDSAWithSHA1 {
		return Failed, "OCSP Response is signed with an algorithm that uses SHA1"
	}
	
	return Passed, "OCSP Response is signed with an algorithm that does not use SHA1"
}

// LintProducedAtDate checks that an OCSP Response ProducedAt date is no more than ProducedAtLimit in the past
// Source: Apple Lints 03 & 05
func LintProducedAtDate(resp *ocsp.Response, leafCert *x509.Certificate) (LintStatus, string) {
	// default assume certificate being checked is a subscriber certificate
	certType := "subscriber certificate"
	producedAtLimit := ProducedAtLimitSubscriber
	if leafCert != nil && leafCert.IsCA {
		certType = "subordinate CA certificate"
		producedAtLimit = ProducedAtLimitCA
	}

	limit, err := time.ParseDuration(producedAtLimit)

	if err != nil {
		return Error, fmt.Sprintf("Could not parse time duration %s", producedAtLimit)
	}

	if time.Since(resp.ProducedAt) > limit {
		return Failed, fmt.Sprintf("OCSP Response producedAt date %s for %s is more than %s in the past", 
			resp.ProducedAt, certType, DurationToString[producedAtLimit])
	}

	return Passed, fmt.Sprintf("OCSP Response producedAt date %s for %s is within %s of the past", 
		resp.ProducedAt, certType, DurationToString[producedAtLimit])
}

// LintThisUpdateDate checks that an OCSP Response ThisUpdate date is no more than ThisUpdateLimit in the past
// Source: Apple Lints 03 & 05
func LintThisUpdateDate(resp *ocsp.Response, leafCert *x509.Certificate) (LintStatus, string) {
	// default assume certificate being checked is a subscriber certificate
	certType := "subscriber certificate"
	thisUpdateLimit := ThisUpdateLimitSubscriber
	if leafCert != nil && leafCert.IsCA {
		certType = "subordinate CA certificate"
		thisUpdateLimit = ThisUpdateLimitCA
	}

	limit, err := time.ParseDuration(thisUpdateLimit)
	if err != nil {
		return Error, fmt.Sprintf("Could not parse time duration %s", thisUpdateLimit)
	}

	if time.Since(resp.ThisUpdate) > limit {
		return Failed, fmt.Sprintf("OCSP Response thisUpdate date %s for %s is more than %s in the past", 
			resp.ThisUpdate, certType, DurationToString[thisUpdateLimit])
		
	}

	return Passed, fmt.Sprintf("OCSP Response thisUpdate date %s for %s is within %s of the past", 
		resp.ThisUpdate, certType, DurationToString[thisUpdateLimit])
	
}
