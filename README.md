# httpsig

`go get github.com/go-fed/httpsig`

Implementation of [HTTP Signatures](https://tools.ietf.org/html/draft-cavage-http-signatures).

Supports many different combinations of MAC, HMAC signing of hash, or RSA signing of hash schemes. Its goals are:

* Have a very simple interface for signing and validating
* Support a variety of signing algorithms and combinations
* Support setting either headers (`Authorization` or `Signature`)
* Remaining flexible with headers included in the signing string
* Support both HTTP requests and responses
* Explicitly not support known-cryptographically weak algorithms
