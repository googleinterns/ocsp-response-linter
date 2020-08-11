# OCSP Response Linter

[![Go Report Card](https://goreportcard.com/badge/github.com/googleinterns/ocsp-response-linter)](https://goreportcard.com/report/github.com/googleinterns/ocsp-response-linter)

OCSP Response Linter is a command line tool for fetching as well as linting and verifying OCSP responses.

## Lints and Verifications Sources

The lints and verifications implemented come primarily from [Apple's OCSP Lints and Test Cases](bug1588001.bmoattachments.org/attachment.cgi?id=9160540) and IETF standards set out in [RFC 6960](tools.ietf.org/html/rfc6960)

## Usage

Example usage to fetch and lint/verify the OCSP response given when checking google.com's certificate:

```bash
./ocsp_status google.com:443
```

Example usage to do the same as above but also write the OCSP response to a specified directory

```bash
./ocsp_status -dir=saved_resps/google_resp google.com:443
```

Example usage to lint/verify a locally saved OCSP Response

```bash
./ocsp_status -in ocsp_response
```

## Adding a New Lint or Verification

To be filled out, haven't settled on the design yet

**This is not an officially supported Google product.**
