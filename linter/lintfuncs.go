package linter

import (
	"bytes"
	"crypto/x509"
	"crypto/sha1"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"golang.org/x/crypto/ocsp"
	"time"
)

const (
	ProducedAtLimitSubscriber = "96h"   // 4 days
	ThisUpdateLimitSubscriber = "96h"   // 4 days
	ProducedAtLimitCA         = "8760h" // 365 days
	ThisUpdateLimitCA         = "8760h" // 365 days
	NextUpdateLimitSubscriber = "240h"  // 10 days
)

// DurationToString is a map mapping durations to more readable strings
var DurationToString = map[string]string{
	ProducedAtLimitSubscriber: "4 days",
	ProducedAtLimitCA:         "365 days",
	NextUpdateLimitSubscriber: "10 days",
}

// CheckStatus checks that the status of the OCSP response matches what the user expects it to be
// Source: Apple Lint 07
func CheckStatus(resp *ocsp.Response, issuerCert *x509.Certificate, lintOpts *LintOpts) (LintStatus, string) {
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

// CheckSignature checks in the ocsp response is signed with an algorithm that uses SHA1
// Source: Apple Lints 10 & 12
func CheckSignature(resp *ocsp.Response, issuerCert *x509.Certificate, lintOpts *LintOpts) (LintStatus, string) {
	if resp.Signature == nil || len(resp.Signature) == 0 {
		return Failed, "OCSP Response is not signed"
	}

	algo := resp.SignatureAlgorithm

	// These are all the SHA1 based algorithms, see https://godoc.org/crypto/x509#SignatureAlgorithm
	if algo == x509.SHA1WithRSA || algo == x509.DSAWithSHA1 || algo == x509.ECDSAWithSHA1 {
		return Failed, "OCSP Response is signed with an algorithm that uses SHA1"
	}

	return Passed, "OCSP Response is signed with an algorithm that does not use SHA1"
}

// CheckResponder checks that the OCSP Responder is either the issuing CA or a delegated responder
// issued by the issuing CA either by comparing public key hashes or names
// Source: Apple Lint 13
func CheckResponder(resp *ocsp.Response, issuerCert *x509.Certificate, lintOpts *LintOpts) (LintStatus, string) {
	if issuerCert == nil {
		return Unknown, "Issuer certificate not provided, can't check responder"		
	}
	// Exactly one of RawResponderName and ResponderKeyHash is set.
	ocspResponder := resp.RawResponderName

	// check if OCSP Responder is Issuing CA
	if ocspResponder == nil {
		// get SHA-1 hash of issuer public key
		var keyBytes []byte

		// need to add more cases in the future
		switch pub := issuerCert.PublicKey.(type) {
			case *rsa.PublicKey:
				keyBytes = x509.MarshalPKCS1PublicKey(pub)
			case *ecdsa.PublicKey:
				keyBytes = elliptic.MarshalCompressed(pub.Curve, pub.X, pub.Y)
			default:
				return Unknown, fmt.Sprintf("Public Key type %T is not implemented", pub)
		}

		issuerKeyHash := sha1.Sum(keyBytes)

		if bytes.Equal(resp.ResponderKeyHash, issuerKeyHash[:]) {
			return Passed, "OCSP Responder is the Issuing CA"
		}
	}

	if bytes.Equal(ocspResponder, issuerCert.RawSubject) {
		return Passed, "OCSP Responder is the Issuing CA"
	}

	ocspResponderCert := resp.Certificate
	if ocspResponderCert == nil {
		return Failed, "Unknown responder: responder did not provide its certificate in OCSP response"
	}

	// check if OCSP responder is issued by Issuing CA
	err := ocspResponderCert.CheckSignatureFrom(issuerCert)
	if err != nil {
		return Failed, "OCSP Responder is not issued by the Issuing CA"
	}

	return Passed, "OCSP Responder is issued by the Issuing CA"
}

// LintProducedAtDate checks that an OCSP Response ProducedAt date is no more than ProducedAtLimit in the past
// Source: Apple Lints 03 & 05
func LintProducedAtDate(resp *ocsp.Response, issuerCert *x509.Certificate, lintOpts *LintOpts) (LintStatus, string) {
	// default assume certificate being checked is a subscriber certificate
	producedAtLimit := ProducedAtLimitSubscriber
	if lintOpts.LeafCertType == CA {
		producedAtLimit = ProducedAtLimitCA
	}

	limit, err := time.ParseDuration(producedAtLimit)

	if err != nil {
		return Error, fmt.Sprintf("Could not parse time duration %s", producedAtLimit)
	}

	if time.Since(resp.ProducedAt) > limit {
		return Failed, fmt.Sprintf("OCSP Response producedAt date %s for %s is more than %s in the past",
			resp.ProducedAt, lintOpts.LeafCertType, DurationToString[producedAtLimit])
	}

	return Passed, fmt.Sprintf("OCSP Response producedAt date %s for %s is within %s in the past",
		resp.ProducedAt, lintOpts.LeafCertType, DurationToString[producedAtLimit])
}

// LintThisUpdateDate checks that an OCSP Response ThisUpdate date is no more than ThisUpdateLimit in the past
// Source: Apple Lints 03 & 05
func LintThisUpdateDate(resp *ocsp.Response, issuerCert *x509.Certificate, lintOpts *LintOpts) (LintStatus, string) {
	// default assume certificate being checked is a subscriber certificate
	thisUpdateLimit := ThisUpdateLimitSubscriber
	if lintOpts.LeafCertType == CA {
		thisUpdateLimit = ThisUpdateLimitCA
	}

	limit, err := time.ParseDuration(thisUpdateLimit)
	if err != nil {
		return Error, fmt.Sprintf("Could not parse time duration %s", thisUpdateLimit)
	}

	if time.Since(resp.ThisUpdate) > limit {
		return Failed, fmt.Sprintf("OCSP Response thisUpdate date %s for %s is more than %s in the past",
			resp.ThisUpdate, lintOpts.LeafCertType, DurationToString[thisUpdateLimit])

	}

	return Passed, fmt.Sprintf("OCSP Response thisUpdate date %s for %s is within %s in the past",
		resp.ThisUpdate, lintOpts.LeafCertType, DurationToString[thisUpdateLimit])

}

// LintNextUpdateDate checks that an OCSP Response NextUpdate date is no more than NextUpdateLimitSubscriber in the past
// Source: Apple Lint 04
func LintNextUpdateDate(resp *ocsp.Response, issuerCert *x509.Certificate, lintOpts *LintOpts) (LintStatus, string) {
	if lintOpts.LeafCertType == CA {
		return Passed, "OCSP Response nextUpdate lint not applicable to CA certificates"
	}

	limit, err := time.ParseDuration(NextUpdateLimitSubscriber)
	if err != nil {
		return Error, fmt.Sprintf("Could not parse time duration %s", NextUpdateLimitSubscriber)
	}

	if resp.NextUpdate.Sub(resp.ThisUpdate) > limit {
		return Failed, fmt.Sprintf("OCSP Response NextUpdate date %s is more than %s after ThisUpdate date %s",
			resp.NextUpdate, DurationToString[NextUpdateLimitSubscriber], resp.ThisUpdate)

	}

	return Passed, fmt.Sprintf("OCSP Response NextUpdate date %s is within %s after ThisUpdate date %s",
		resp.NextUpdate, DurationToString[NextUpdateLimitSubscriber], resp.ThisUpdate)

}

// LintStatusForNonIssuedCert checks that an OCSP response for a non-issued certificate does not have status Good
// Source: Apple Lint 06
func LintStatusForNonIssuedCert(resp *ocsp.Response, issuerCert *x509.Certificate, lintOpts *LintOpts) (LintStatus, string) {
	if !lintOpts.LeafCertNonIssued {
		return Passed, "OCSP Response is for issued certificate"
	}

	if resp.Status != ocsp.Good {
		return Passed, "OCSP Response for non-issued certificate does not have status Good"
	}

	return Failed, "OCSP Response for non-issued certificate has status Good"
}
