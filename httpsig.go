// Implements HTTP request and response signing and verification. Supports the
// major MAC and asymmetric key signature algorithms. It has several safety
// restrictions: One, none of the widely known non-cryptographically safe
// algorithms are permitted; Two, the RSA SHA256 algorithms must be available in
// the binary (and it should, barring export restrictions); Finally, the library
// assumes either the 'Authorizationn' or 'Signature' headers are to be set (but
// not both).
package httpsig

import (
	"crypto"
	"fmt"
	"net/http"
)

// Algorithm specifies a cryptography secure algorithm for signing HTTP requests
// and responses.
type Algorithm string

const (
	defaultAlgorithm = RSA_SHA256
)

func init() {
	// This should guarantee that at runtime the defaultAlgorithm will not
	// result in errors when fetching a macer or signer (see algorithms.go)
	if ok, err := isAvailable(defaultAlgorithm); err != nil {
		panic(err)
	} else if !ok {
		panic(fmt.Sprintf("the default httpsig algorithm is unavailable: %q", defaultAlgorithm))
	}
}

const (
	HMAC_SHA224      Algorithm = hmacPrefix + "-" + sha224String
	HMAC_SHA256                = hmacPrefix + "-" + sha256String
	HMAC_SHA384                = hmacPrefix + "-" + sha384String
	HMAC_SHA512                = hmacPrefix + "-" + sha512String
	HMAC_RIPEMD160             = hmacPrefix + "-" + ripemd160String
	HMAC_SHA3_224              = hmacPrefix + "-" + sha3_224String
	HMAC_SHA3_256              = hmacPrefix + "-" + sha3_256String
	HMAC_SHA3_384              = hmacPrefix + "-" + sha3_384String
	HMAC_SHA3_512              = hmacPrefix + "-" + sha3_512String
	HMAC_SHA512_224            = hmacPrefix + "-" + sha512_224String
	HMAC_SHA512_256            = hmacPrefix + "-" + sha512_256String
	HMAC_BLAKE2S_256           = hmacPrefix + "-" + blake2s_256String
	HMAC_BLAKE2B_256           = hmacPrefix + "-" + blake2b_256String
	HMAC_BLAKE2B_384           = hmacPrefix + "-" + blake2b_384String
	HMAC_BLAKE2B_512           = hmacPrefix + "-" + blake2b_512String
	BLAKE2S_256                = blake2s_256String
	BLAKE2B_256                = blake2b_256String
	BLAKE2B_384                = blake2b_384String
	BLAKE2B_512                = blake2b_512String
	RSA_SHA224                 = rsaPrefix + "-" + sha224String
	// RSA_SHA256 is the default algorithm.
	RSA_SHA256      = rsaPrefix + "-" + sha256String
	RSA_SHA384      = rsaPrefix + "-" + sha384String
	RSA_SHA512      = rsaPrefix + "-" + sha512String
	RSA_RIPEMD160   = rsaPrefix + "-" + ripemd160String
	RSA_SHA3_224    = rsaPrefix + "-" + sha3_224String
	RSA_SHA3_256    = rsaPrefix + "-" + sha3_256String
	RSA_SHA3_384    = rsaPrefix + "-" + sha3_384String
	RSA_SHA3_512    = rsaPrefix + "-" + sha3_512String
	RSA_SHA512_224  = rsaPrefix + "-" + sha512_224String
	RSA_SHA512_256  = rsaPrefix + "-" + sha512_256String
	RSA_BLAKE2S_256 = rsaPrefix + "-" + blake2s_256String
	RSA_BLAKE2B_256 = rsaPrefix + "-" + blake2b_256String
	RSA_BLAKE2B_384 = rsaPrefix + "-" + blake2b_384String
	RSA_BLAKE2B_512 = rsaPrefix + "-" + blake2b_512String
)

// HTTP Signatures can be applied to either the "Authorization" or "Signature"
// HTTP header
type SignatureScheme string

const (
	Signature     SignatureScheme = "Signature"
	Authorization                 = "Authorization"
)

// Signers will sign HTTP requests or responses based on the algorithms and
// headers selected at creation time.
type Signer interface {
	SignRequest(pKey crypto.PrivateKey, pubKeyId string, r *http.Request) error
	SignResponse(pKey crypto.PrivateKey, pubKeyId string, r http.ResponseWriter) error
}

// NewSigner creates a new Signer with the provided algorithm preferences to
// make http signatures. Only the first available algorithm will be used, which
// is returned by this function along with the Signer. If none of the preferred
// algorithms were available, then the default algorithm is used. The headers
// specified will be included into the HTTP signatures.
//
// The provided scheme determines which header is populated with the HTTP
// Signature.
//
// An error is returned if an unknown or a known cryptographically insecure
// Algorithm is provided.
func NewSigner(prefs []Algorithm, headers []string, scheme SignatureScheme) (Signer, Algorithm, error) {
	for _, pref := range prefs {
		if ok, err := isAvailable(string(pref)); err != nil {
			return nil, "", err
		} else if !ok {
			continue
		}
		s, err := newSigner(pref, headers, scheme)
		return s, pref, err
	}
	s, err := newSigner(defaultAlgorithm, headers, scheme)
	return s, defaultAlgorithm, err
}

// TODO: Verification

func newSigner(algo Algorithm, headers []string, scheme SignatureScheme) (Signer, error) {
	s, err := signerFromString(string(algo))
	if err == nil {
		a := &asymmSigner{
			s:            s,
			headers:      headers,
			targetHeader: scheme,
		}
		return a, nil
	}
	m, err := macerFromString(string(algo))
	if err != nil {
		return nil, fmt.Errorf("no crypto implementation available for %q", algo)
	}
	c := &macSigner{
		m:            m,
		headers:      headers,
		targetHeader: scheme,
	}
	return c, nil
}
