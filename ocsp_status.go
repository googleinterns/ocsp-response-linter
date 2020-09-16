// Package main provides the main command line functionality
package main

import (
	"crypto"
	"crypto/x509"
	"flag"
	"fmt"
	"github.com/googleinterns/ocsp-response-linter/linter"
	"github.com/googleinterns/ocsp-response-linter/ocsptools"
	"github.com/googleinterns/ocsp-response-linter/ocsptools/helpers"
	"golang.org/x/crypto/ocsp"
	"net/http"
)

// checkFromFile takes a path to an OCSP Response file and then reads, parses, and lints it
func checkFromFile(tools ocsptools.ToolsInterface, respFile string) (*ocsp.Response, error) {
	ocspResp, err := tools.ReadOCSPResp(respFile)
	if err != nil {
		return nil, err
	}

	return ocspResp, nil
}

// checkFromCert takes a path to an ASN.1 DER encoded certificate file and
// constructs and sends an OCSP request then parses and lints the OCSP response
func checkFromCert(tools ocsptools.ToolsInterface, certFile string, issuerCert *x509.Certificate,
	isPost bool, ocspURL string, dir string, hash crypto.Hash) (*ocsp.Response, *x509.Certificate, error) {
	reqMethod := http.MethodGet
	if isPost {
		reqMethod = http.MethodPost
	}

	leafCert, err := tools.ParseCertificateFile(certFile)
	if err != nil {
		return nil, nil, fmt.Errorf("Error parsing certificate from certificate file: %w", err)
	}

	h := helpers.Helpers{}

	if issuerCert == nil {
		issuerCert, err = tools.GetIssuerCertFromLeafCert(h, leafCert)
		if err != nil {
			return nil, nil, fmt.Errorf("Error getting issuer certificate from certificate: %w", err)
		}
	}

	ocspResp, err := tools.FetchOCSPResp(h, ocspURL, dir, leafCert, issuerCert, reqMethod, hash)
	if err != nil {
		return nil, nil, fmt.Errorf("Error fetching OCSP response: %w", err)
	}

	return ocspResp, issuerCert, nil
}

// checkFromURL takes a server URL and constructs and sends an OCSP request to
// check that URL's certificate then parses and lints the OCSP response
func checkFromURL(tools ocsptools.ToolsInterface, serverURL string, issuerCert *x509.Certificate, shouldPrint bool, 
	isPost bool, noStaple bool, ocspURL string, dir string, hash crypto.Hash) (*ocsp.Response, *x509.Certificate, error) {
	certChain, ocspResp, err := tools.GetCertChainAndStapledResp(serverURL)
	if err != nil {
		return nil, nil, err
	}

	leafCert := certChain[0] // the certificate we want to send to the CA

	h := helpers.Helpers{}

	if issuerCert == nil {
		issuerCert, err = tools.GetIssuerCertFromLeafCert(h, leafCert)
		if err != nil {
			fmt.Println("Couldn't get issuer certificate from leaf certificate, taking the second certificate in the chain as the issuer certificate")
			issuerCert = certChain[1]
		}
	}

	if shouldPrint {
		err = ocsptools.PrintCert(leafCert)
		if err != nil {
			return nil, nil, fmt.Errorf("Error printing certificate: %w", err)
		}
	}

	var parsedResp *ocsp.Response

	if ocspResp == nil || noStaple {
		reqMethod := http.MethodGet
		if isPost {
			reqMethod = http.MethodPost
		}

		h := helpers.Helpers{}

		parsedResp, err = tools.FetchOCSPResp(h, ocspURL, dir, leafCert, issuerCert, reqMethod, hash)
		if err != nil {
			return nil, nil, fmt.Errorf("Error fetching OCSP response: %w", err)
		}
	} else {
		fmt.Println("Stapled OCSP Response")

		parsedResp, err = ocsp.ParseResponse(ocspResp, issuerCert)
		if err != nil {
			return nil, nil, fmt.Errorf("Error parsing OCSP response: %w", err)
		}
	}

	return parsedResp, issuerCert, nil
}

// main parses the users commandline arguments & flags and then runs the appropriate functions
func main() {
	// TODO: extract flag descriptions into constants?
	// TODO: I'm not sure if I should support putting multiple ocsp requests in at once anymore
	inresp := flag.Bool("inresp", false, "Whether to read in an OCSP response or not")
	incert := flag.Bool("incert", false, "Whether to read in certificate file or not")
	issuerFile := flag.String("issuercert", "", "Issuing certificate file")
	ocspURL := flag.String("ocspurl", "", "OCSP responder url to send request to, default fetch from certificate")
	shouldPrint := flag.Bool("print", false, "Whether to print certificate or not") // may remove this print flag
	isPost := flag.Bool("post", false, "Whether to use POST for OCSP request")
	dir := flag.String("dir", "", "Where to write OCSP response")
	noStaple := flag.Bool("nostaple", false, "Whether to send an OCSP request regardless of if there is a stapled OCSP response")

	expectGood := flag.Bool("expectgood", false, "Whether to expect good OCSP response")
	expectRevoke := flag.Bool("expectrevoke", false, "Whether to expect revoked OCSP response")

	caCert := flag.Bool("cacert", false, "Whether certificate is for a CA")
	nonIssuedCert := flag.Bool("nonissuedcert", false, "Whether certificate is not issued by CA")

	verbose := flag.Bool("v", false, "Whether to use verbose printing for printing lints")

	flag.Parse()

	tools := ocsptools.Tools{}

	if *inresp && *incert {
		panic("This tool can only parse one file format at a time. Please use only one of -inresp or -incert.")
	}

	if *expectGood && *expectRevoke {
		panic("Please use only one of -expectpass or -expectrevoke.")
	}

	// create lint opts
	leafCertType := linter.Subscriber
	if *caCert {
		leafCertType = linter.CA
	}

	expectedStatus := linter.None
	if *expectGood {
		expectedStatus = linter.Good
	} else if *expectRevoke {
		expectedStatus = linter.Revoked
	}

	lintOpts := &linter.LintOpts{
		LeafCertType: leafCertType,
		LeafCertNonIssued: *nonIssuedCert,
		ExpectedStatus: expectedStatus,
	}

	if len(flag.Args()) == 0 {
		panic("No argument given")
	}

	arg := flag.Args()[0]

	var err error

	var issuerCert *x509.Certificate
	if *issuerFile != "" {
		issuerCert, err = tools.ParseCertificateFile(*issuerFile)
		if err != nil {
			panic(fmt.Sprintf("Error parsing certificate from certificate file: %s", err))
		}
	}

	var ocspResp *ocsp.Response

	if *inresp {
		// arg is a respFile
		ocspResp, err = checkFromFile(tools, arg)
		if err != nil {
			panic(fmt.Sprintf("Error checking OCSP Response file %s: %s", arg, err))
		}
	} else if *incert {
		// arg is a certFile
		ocspResp, issuerCert, err = checkFromCert(tools, arg, issuerCert, *isPost, *ocspURL, *dir, crypto.SHA256)
		if err != nil {
			fmt.Printf("Validation failed for sending OCSP Request encoded with SHA256: %s \n\n", err)

			ocspResp, issuerCert, err = checkFromCert(tools, arg, issuerCert, *isPost, *ocspURL, *dir, crypto.SHA1)
			if err != nil {
				panic(fmt.Sprintf("Error checking certificate file %s: %s", arg, err))
			}
		}
	} else {
		// arg is a serverURL
		ocspResp, issuerCert, err = checkFromURL(tools, arg, issuerCert, *shouldPrint, *isPost, *noStaple, *ocspURL, *dir, crypto.SHA256)
		if err != nil {
			fmt.Printf("Validation failed for sending OCSP Request encoded with SHA256: %s \n\n", err)

			ocspResp, issuerCert, err = checkFromURL(tools, arg, issuerCert, *shouldPrint, *isPost, *noStaple, *ocspURL, *dir, crypto.SHA1)
			if err != nil {
				panic(fmt.Sprintf("Error checking server URL %s: %s", arg, err))
			}
		}
	}

	linter.Linter{}.LintOCSPResp(ocspResp, issuerCert, lintOpts, *verbose)
}
