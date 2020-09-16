# OCSP Response Linter

[![Go Report Card](https://goreportcard.com/badge/github.com/googleinterns/ocsp-response-linter)](https://goreportcard.com/report/github.com/googleinterns/ocsp-response-linter)

OCSP Response Linter is a command line tool for fetching, linting, and verifying OCSP responses.

**This is not an officially supported Google product.**

## Lints and Verifications Sources

We distinguish between lints and verifications as follows: 
- A lint is a requirement that can be checked using only the OCSP response (e.g. ensuring that the producedAt date field of a response is no more than four days in the past)
- A verification is a requirement that necessitates querying an outside service and may run while in the process of fetching the OCSP Response (e.g. checking that an OCSP response is delivered in 10 seconds after sending the request)

The lints and verifications implemented come primarily from [Apple's OCSP Lints and Test Cases](http://bug1588001.bmoattachments.org/attachment.cgi?id=9160540) and IETF standards set out in [RFC 6960](http://tools.ietf.org/html/rfc6960).

## Usage

The OCSP Response Linter allows users to specify three different types of input. The first (default) method is to supply a server URL

`./ocsp_status [url] ...`

The second method is to supply ASN.1 DER encoded a certificate file that should be sent to an OCSP responder. Please note that the certificate must contain an OCSP responder URL and issuer certificate URL or else the tool will not be able to generate the OCSP request.

`./ocsp_status -incert [certfile] ...`

The third method is to supply an OCSP response file. If this method is chosen, verifications cannot be run.

`./ocsp_status -inresp [respfile] ...`

A complete table of available flags:

| Flag    | Description                                           | Example                                                    |
| --------| ------------------------------------------------------| ---------------------------------------------------------- |
| inresp  | Read in OCSP response file                       | `./ocsp_status -inresp google_resp` |
| incert  | Read in certificate file (must be ASN.1 DER encoded) | `./ocsp_status -incert google_cert.der` |
| issuercert | Read in issuer certificate file (must be ASN.1 DER encoded) | `./ocsp_status -issuercert="googleissuer_cert.der" -incert google_cert.der` |
| ocspurl | Read in CA url to send the OCSP request to           | `./ocsp_status -ocspurl=http://ocsp.google.com google.com:443` |
| post    | Use POST to send the OCSP request (default is GET)    | `./ocsp_status -post google.com:443` |
| dir     | Write the OCSP response to a file                     | `./ocsp_status -dir=google_resp google.com:443`|
| nostaple| Don't use the stapled OCSP response (only use with server URL) | `./ocsp_status -nostaple google.com:443` |
| expectgood | Tell the linter to expect a good OCSP response | `./ocsp_status -expectgood google.com:443` |
| expectrevoked | Tell the linter to expect a revoked OCSP response | `./ocsp_status -expectrevoked revokedgrc.com:443` |
| cacert | Tell the linter that you are inputting a CA cert | `./ocsp_status -cacert -incert googleissuer_cert.der` |
| nonissuedcert | Tell the linter that you are inputting a non-issued cert | `./ocsp_status -nonissuedcert -ocspurl=ocsp.google.com facebook.com:443` |
| v | Print information on all lints (including passed lints) | `./ocsp_status -verbose google.com:443`|

Note you can also do `./ocsp_status -help` to see a list of all possible flags and their descriptions.
