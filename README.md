# OCSP Response Linter

[![Go Report Card](https://goreportcard.com/badge/github.com/googleinterns/ocsp-response-linter)](https://goreportcard.com/report/github.com/googleinterns/ocsp-response-linter)

OCSP Response Linter is a command line tool for fetching, linting, and verifying OCSP responses.

**This is not an officially supported Google product.**

## Lints and Verifications Sources

We distinguish between lints and verifications as follows: 
- A lint is a requirement that can be checked using only the OCSP response (e.g. ensuring that the producedAt date field of a response is no more than four days in the past)
- A verification is a requirement that necessitates querying an outside service and may run while in the process of fetching the OCSP Response (e.g. checking that an OCSP response is delivered in 10 seconds after sending the request)

The lints and verifications implemented come primarily from [Apple's OCSP Lints and Test Cases](bug1588001.bmoattachments.org/attachment.cgi?id=9160540) and IETF standards set out in [RFC 6960](tools.ietf.org/html/rfc6960).

## Usage

The OCSP Response Linter allows users to specify three different types of input. The first (default) method is to supply server URL(s)

`./ocsp_status [url1] [url2] ...`

The second method is to supply ASN.1 DER encoded certificate file(s) that should be sent to an OCSP responder. Please note that the certificate must contain an OCSP responder URL and issuer certificate URL or else the tool will not be able to generate the OCSP request.

`./ocsp_status -incert [certfile1] [certfile2] ...`

The third method is to supply the OCSP response file(s) itself. If this method is chosen, verifications checking to see if fetching the OCSP Response meets IETF standards cannot be run.

`./ocsp_status -inresp [respfile1] [respfile2] ...`

The OCSP Response Linter will loop through all inputs provided and lint/verify each resulting OCSP response.

A complete table of available flags:

| Flag    | Description                                           | Example                                                    |
| --------| ------------------------------------------------------| ---------------------------------------------------------- |
| inresp  | Read in OCSP response(s) files                        | `./ocsp_status -inresp resps/google_resp` |
| incert  | Read in certificate files (must be ASN.1 DER encoded) | `./ocsp_status -incert certs/google_cert.der` |
| ocspurl | Specify the url to send the OCSP request to           | `./ocsp_status -ocspurl=http://ocsp.pki.goog/gts1o1core google.com:443` |
| post    | Use POST to send the OCSP request (instead of GET)    | `./ocsp_status -post google.com:443` |
| dir     | Write the OCSP response to a file                     | `./ocsp_status -dir=resps/google_resp google.com:443`|
| nostaple| Don't use the stapled OCSP response (only use with server URLs) | `./ocsp_status -nostaple google.com:443` |
