// Package main provides the main command line functionality
package main

import (
	"crypto"
	"flag"
	"fmt"
	"github.com/googleinterns/ocsp-response-linter/linter"
	"github.com/googleinterns/ocsp-response-linter/ocsptools"
	"github.com/googleinterns/ocsp-response-linter/ocsptools/helpers"
	"golang.org/x/crypto/ocsp"
	"net/http"
)

// checkFromFile takes a path to an OCSP Response file and then reads, parses, and lints it
func checkFromFile(tools ocsptools.ToolsInterface, linter linter.LinterInterface, respFile string, verbose bool) error {
	ocspResp, err := tools.ReadOCSPResp(respFile)
	if err != nil {
		return err
	}

	linter.LintOCSPResp(ocspResp, verbose)

	return nil
}

// checkFromCert takes a path to an ASN.1 DER encoded certificate file and
// constructs and sends an OCSP request then parses and lints the OCSP response
func checkFromCert(tools ocsptools.ToolsInterface, linter linter.LinterInterface, certFile string, isPost bool, ocspURL string, dir string, hash crypto.Hash, verbose bool) error {
	reqMethod := http.MethodGet
	if isPost {
		reqMethod = http.MethodPost
	}

	leafCert, err := tools.ParseCertificateFile(certFile)
	if err != nil {
		return fmt.Errorf("Error parsing certificate from certificate file: %w", err)
	}

	h := helpers.Helpers{}

	issuerCert, err := tools.GetIssuerCertFromLeafCert(h, leafCert)
	if err != nil {
		return fmt.Errorf("Error getting issuer certificate from certificate: %w", err)
	}

	ocspResp, err := tools.FetchOCSPResp(h, ocspURL, dir, leafCert, issuerCert, reqMethod, hash)
	if err != nil {
		return fmt.Errorf("Error fetching OCSP response: %w", err)
	}

	linter.LintOCSPResp(ocspResp, verbose)

	return nil
}

// checkFromURL takes a server URL and constructs and sends an OCSP request to
// check that URL's certificate then parses and lints the OCSP response
func checkFromURL(tools ocsptools.ToolsInterface, linter linter.LinterInterface, serverURL string, shouldPrint bool, isPost bool, noStaple bool, ocspURL string, dir string, hash crypto.Hash, verbose bool) error {
	certChain, ocspResp, err := tools.GetCertChainAndStapledResp(serverURL)
	if err != nil {
		return err
	}

	leafCert := certChain[0]   // the certificate we want to send to the CA
	issuerCert := certChain[1] // the certificate of the issuer of the leaf cert

	if shouldPrint {
		err = ocsptools.PrintCert(leafCert)
		if err != nil {
			return fmt.Errorf("Error printing certificate: %w", err)
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
			return fmt.Errorf("Error fetching OCSP response: %w", err)
		}
	} else {
		fmt.Println("Stapled OCSP Response")

		parsedResp, err = ocsp.ParseResponse(ocspResp, issuerCert)
		if err != nil {
			return fmt.Errorf("Error parsing OCSP response: %w", err)
		}
	}

	linter.LintOCSPResp(parsedResp, verbose)

	return nil
}

// main parses the users commandline arguments & flags and then runs the appropriate functions
func main() {
	// TODO: extract flag descriptions into constants?
	inresp := flag.Bool("inresp", false, "Whether to read in an OCSP responses or not")
	incert := flag.Bool("incert", false, "Whether to read in certificate files or not")
	ocspurl := flag.String("ocspurl", "", "User provided OCSP url, default fetch from certificate")
	shouldPrint := flag.Bool("print", false, "Whether to print certificate or not") // may remove this print flag
	isPost := flag.Bool("post", false, "Whether to use POST for OCSP request")
	dir := flag.String("dir", "", "Where to write OCSP response, if blank don't write")
	noStaple := flag.Bool("nostaple", false, "Whether to send an OCSP request regardless of if there is a stapled OCSP response")
	verbose := flag.Bool("verbose", false, "Whether to use verbose printing for printing lints")

	flag.Parse()

	tools := ocsptools.Tools{}
	linter := linter.Linter{}
	
	if *inresp && *incert {
		panic("This tool can only parse one file format at a time. Please use only one of -inresp or -incert.")
	}

	if *inresp {
		// reading in OCSP response files
		respFiles := flag.Args()
		for _, respFile := range respFiles {
			err := checkFromFile(tools, linter, respFile, *verbose)
			if err != nil {
				panic(fmt.Errorf("Error checking OCSP Response file %s: %w", respFile, err).Error())
			}
		}
	} else if *incert {
		// reading in certificate files
		certFiles := flag.Args()
		for _, certFile := range certFiles {
			err := checkFromCert(tools, linter, certFile, *isPost, *ocspurl, *dir, crypto.SHA256, *verbose)
			if err == nil {
				return
			}
			fmt.Printf("Validation failed for sending OCSP Request encoded with SHA256: %s \n\n" , err.Error())

			err = checkFromCert(tools, linter, certFile, *isPost, *ocspurl, *dir, crypto.SHA1, *verbose)
			if err != nil {
				panic(fmt.Errorf("Error checking certificate file %s: %w", certFile, err).Error())
			}
		}
	} else {
		// reading in server URLs
		serverURLs := flag.Args()

		for _, serverURL := range serverURLs {
			err := checkFromURL(tools, linter, serverURL, *shouldPrint, *isPost, *noStaple, *ocspurl, *dir, crypto.SHA256, *verbose)
			if err == nil {
				return
			}
			fmt.Printf("Validation failed for sending OCSP Request encoded with SHA256: %s \n\n", err.Error())

			err = checkFromURL(tools, linter, serverURL, *shouldPrint, *isPost, *noStaple, *ocspurl, *dir, crypto.SHA1, *verbose)
			if err != nil {
				panic(fmt.Errorf("Error checking server URL %s: %w", serverURL, err).Error())
			}
		}
	}
}
