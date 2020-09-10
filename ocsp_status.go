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
	"strings"
)

// checkFromFile takes a path to an OCSP Response file and then reads, parses, and lints it
func checkFromFile(tools ocsptools.ToolsInterface, linter linter.LinterInterface, respFile string, issuerFile string, verbose bool) error {
	ocspResp, err := tools.ReadOCSPResp(respFile)
	if err != nil {
		return err
	}

	issuerCert, err := tools.ParseCertificateFile(issuerFile)
	if err != nil {
		return fmt.Errorf("Error parsing certificate from certificate file: %w", err)
	}

	linter.LintOCSPResp(ocspResp, issuerCert, verbose)

	return nil
}

// checkFromCert takes a path to an ASN.1 DER encoded certificate file and
// constructs and sends an OCSP request then parses and lints the OCSP response
func checkFromCert(tools ocsptools.ToolsInterface, linter linter.LinterInterface, certFile string, issuerFile string, isPost bool, ocspURL string, dir string, hash crypto.Hash, verbose bool) error {
	reqMethod := http.MethodGet
	if isPost {
		reqMethod = http.MethodPost
	}

	leafCert, err := tools.ParseCertificateFile(certFile)
	if err != nil {
		return fmt.Errorf("Error parsing certificate from certificate file: %w", err)
	}

	issuerCert, err := tools.ParseCertificateFile(issuerFile)
	if err != nil {
		return fmt.Errorf("Error parsing certificate from certificate file: %w", err)
	}

	h := helpers.Helpers{}

	if issuerCert == nil {
		issuerCert, err = tools.GetIssuerCertFromLeafCert(h, leafCert)
		if err != nil {
			return fmt.Errorf("Error getting issuer certificate from certificate: %w", err)
		}
	}

	ocspResp, err := tools.FetchOCSPResp(h, ocspURL, dir, leafCert, issuerCert, reqMethod, hash)
	if err != nil {
		return fmt.Errorf("Error fetching OCSP response: %w", err)
	}

	linter.LintOCSPResp(ocspResp, leafCert, verbose)

	return nil
}

// checkFromURL takes a server URL and constructs and sends an OCSP request to
// check that URL's certificate then parses and lints the OCSP response
func checkFromURL(tools ocsptools.ToolsInterface, linter linter.LinterInterface, serverURL string, issuerFile string, shouldPrint bool, isPost bool, noStaple bool, ocspURL string, dir string, hash crypto.Hash, verbose bool) error {
	certChain, ocspResp, err := tools.GetCertChainAndStapledResp(serverURL)
	if err != nil {
		return err
	}

	leafCert := certChain[0]   // the certificate we want to send to the CA

	issuerCert, err := tools.ParseCertificateFile(issuerFile)
	if err != nil {
		return fmt.Errorf("Error parsing certificate from certificate file: %w", err)
	}

	if issuerCert == nil {
		issuerCert = certChain[1] // the certificate of the issuer of the leaf cert
	}

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

	linter.LintOCSPResp(parsedResp, leafCert, verbose)

	return nil
}

// main parses the users commandline arguments & flags and then runs the appropriate functions
func main() {
	// TODO: extract flag descriptions into constants?
	inresp := flag.Bool("inresp", false, "Whether to read in an OCSP responses or not")
	incert := flag.Bool("incert", false, "Whether to read in certificate files or not")
	issuerFile := flag.String("issuercert", "", "Space separated list of issuing certificate files")
	ocspurl := flag.String("ocspurl", "", "Space separated list of OCSP urls to send requests to, default fetch from certificate")
	shouldPrint := flag.Bool("print", false, "Whether to print certificate or not") // may remove this print flag
	isPost := flag.Bool("post", false, "Whether to use POST for OCSP request")
	dir := flag.String("dir", "", "Where to write OCSP response")
	noStaple := flag.Bool("nostaple", false, "Whether to send an OCSP request regardless of if there is a stapled OCSP response")
	verbose := flag.Bool("verbose", false, "Whether to use verbose printing for printing lints")

	flag.Parse()

	tools := ocsptools.Tools{}
	linter := linter.Linter{}
	
	if *inresp && *incert {
		panic("This tool can only parse one file format at a time. Please use only one of -inresp or -incert.")
	}

	var issuerFiles []string
	if *issuerFile != "" {
		issuerFiles = strings.Split(*issuerFile, " ")
	}

	var ocspURLs []string
	if *ocspurl != "" {
		ocspURLs = strings.Split(*ocspurl, " ")
	}

	args := flag.Args()
	for idx, arg := range args {
		iFile := ""
		if idx < len(issuerFiles) {
			iFile = issuerFiles[idx]
		}

		ocspURL := ""
		if idx < len(ocspURLs) {
			ocspURL = ocspURLs[idx]
		}

		if *inresp {
			// arg is a respFile
			err := checkFromFile(tools, linter, arg, iFile, *verbose)
			if err != nil {
				fmt.Printf("Error checking OCSP Response file %s: %s \n\n", arg, err.Error())
			}
		} else if *incert {
			// arg is a certFile
			err := checkFromCert(tools, linter, arg, iFile, *isPost, ocspURL, *dir, crypto.SHA256, *verbose)
			if err == nil {
				continue
			}
			fmt.Printf("Validation failed for sending OCSP Request encoded with SHA256: %s \n\n" , err.Error())

			err = checkFromCert(tools, linter, arg, iFile, *isPost, ocspURL, *dir, crypto.SHA1, *verbose)
			if err != nil {
				fmt.Printf("Error checking certificate file %s: %s \n\n", arg, err.Error())
			}
		} else {
			// arg is a serverURL
			err := checkFromURL(tools, linter, arg, iFile, *shouldPrint, *isPost, *noStaple, ocspURL, *dir, crypto.SHA256, *verbose)
			if err == nil {
				continue
			}
			fmt.Printf("Validation failed for sending OCSP Request encoded with SHA256: %s \n\n", err.Error())

			err = checkFromURL(tools, linter, arg, iFile, *shouldPrint, *isPost, *noStaple, ocspURL, *dir, crypto.SHA1, *verbose)
			if err != nil {
				fmt.Printf("Error checking server URL %s: %s \n\n", arg, err.Error())
			}
		}
	}
}
