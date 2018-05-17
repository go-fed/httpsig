package httpsig

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	testUrl    = "foo.net/bar/baz?q=test&r=ok"
	testDate   = "Tue, 07 Jun 2014 20:51:35 GMT"
	testDigest = "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE="
	testMethod = "GET"
)

type httpsigTest struct {
	name                       string
	prefs                      []Algorithm
	headers                    []string
	scheme                     SignatureScheme
	privKey                    crypto.PrivateKey
	pubKey                     crypto.PublicKey
	pubKeyId                   string
	expectedAlgorithm          Algorithm
	expectErrorSigningResponse bool
}

var (
	privKey *rsa.PrivateKey
	macKey  []byte
	tests   []httpsigTest
)

func init() {
	var err error
	privKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	macKey = make([]byte, 128)
	err = readFullFromCrypto(macKey)
	if err != nil {
		panic(err)
	}
	tests = []httpsigTest{
		{
			name:              "rsa signature",
			prefs:             []Algorithm{RSA_SHA512},
			headers:           []string{"Date", "Digest"},
			scheme:            Signature,
			privKey:           privKey,
			pubKey:            privKey.Public(),
			pubKeyId:          "pubKeyId",
			expectedAlgorithm: RSA_SHA512,
		},
		{
			name:              "hmac signature",
			prefs:             []Algorithm{HMAC_SHA256},
			headers:           []string{"Date", "Digest"},
			scheme:            Signature,
			privKey:           macKey,
			pubKey:            macKey,
			pubKeyId:          "pubKeyId",
			expectedAlgorithm: HMAC_SHA256,
		},
		{
			name:              "rsa authorization",
			prefs:             []Algorithm{RSA_SHA512},
			headers:           []string{"Date", "Digest"},
			scheme:            Authorization,
			privKey:           privKey,
			pubKey:            privKey.Public(),
			pubKeyId:          "pubKeyId",
			expectedAlgorithm: RSA_SHA512,
		},
		{
			name:              "hmac authorization",
			prefs:             []Algorithm{HMAC_SHA256},
			headers:           []string{"Date", "Digest"},
			scheme:            Authorization,
			privKey:           macKey,
			pubKey:            macKey,
			pubKeyId:          "pubKeyId",
			expectedAlgorithm: HMAC_SHA256,
		},
		{
			name:              "default algo",
			headers:           []string{"Date", "Digest"},
			scheme:            Signature,
			privKey:           privKey,
			pubKey:            privKey.Public(),
			pubKeyId:          "pubKeyId",
			expectedAlgorithm: RSA_SHA256,
		},
		{
			name:              "default headers",
			prefs:             []Algorithm{RSA_SHA512},
			scheme:            Signature,
			privKey:           privKey,
			pubKey:            privKey.Public(),
			pubKeyId:          "pubKeyId",
			expectedAlgorithm: RSA_SHA512,
		},
		{
			name:              "different pub key id",
			prefs:             []Algorithm{RSA_SHA512},
			headers:           []string{"Date", "Digest"},
			scheme:            Signature,
			privKey:           privKey,
			pubKey:            privKey.Public(),
			pubKeyId:          "i write code that sucks",
			expectedAlgorithm: RSA_SHA512,
		},
		{
			name:                       "with request target",
			prefs:                      []Algorithm{RSA_SHA512},
			headers:                    []string{"Date", "Digest", RequestTarget},
			scheme:                     Signature,
			privKey:                    privKey,
			pubKey:                     privKey.Public(),
			pubKeyId:                   "pubKeyId",
			expectedAlgorithm:          RSA_SHA512,
			expectErrorSigningResponse: true,
		},
	}

}

func toSignatureParameter(k, v string) string {
	return fmt.Sprintf("%s%s%s%s%s", k, parameterKVSeparater, parameterValueDelimiter, v, parameterValueDelimiter)
}

func toHeaderSignatureParameters(k string, vals []string) string {
	if len(vals) == 0 {
		vals = defaultHeaders
	}
	v := strings.Join(vals, headerParameterValueDelim)
	k = strings.ToLower(k)
	v = strings.ToLower(v)
	return fmt.Sprintf("%s%s%s%s%s", k, parameterKVSeparater, parameterValueDelimiter, v, parameterValueDelimiter)
}

func TestNewSigner(t *testing.T) {
	for _, test := range tests {
		s, a, err := NewSigner(test.prefs, test.headers, test.scheme)
		if err != nil {
			t.Fatalf("%q: %s", test.name, err)
		}
		if a != test.expectedAlgorithm {
			t.Fatalf("%q: got %s, want %s", test.name, a, test.expectedAlgorithm)
		}
		// Test request signing
		req, err := http.NewRequest(testMethod, testUrl, nil)
		if err != nil {
			t.Fatalf("%q: %s", test.name, err)
		}
		req.Header.Set("Date", testDate)
		req.Header.Set("Digest", testDigest)
		err = s.SignRequest(test.privKey, test.pubKeyId, req)
		if err != nil {
			t.Fatalf("%q: %s", test.name, err)
		}
		vals, ok := req.Header[string(test.scheme)]
		if !ok {
			t.Fatalf("%q: not in header %s", test.name, test.scheme)
		}
		if len(vals) != 1 {
			t.Fatalf("%q: too many in header %s: %d", test.name, test.scheme, len(vals))
		}
		if p := toSignatureParameter(keyIdParameter, test.pubKeyId); !strings.Contains(vals[0], p) {
			t.Fatalf("%q: %s\ndoes not contain\n%s", test.name, vals[0], p)
		} else if p := toSignatureParameter(algorithmParameter, string(test.expectedAlgorithm)); !strings.Contains(vals[0], p) {
			t.Fatalf("%q: %s\ndoes not contain\n%s", test.name, vals[0], p)
		} else if p := toHeaderSignatureParameters(headersParameter, test.headers); !strings.Contains(vals[0], p) {
			t.Fatalf("%q: %s\ndoes not contain\n%s", test.name, vals[0], p)
		} else if !strings.Contains(vals[0], signatureParameter) {
			t.Fatalf("%q: %s\ndoes not contain\n%s", test.name, vals[0], signatureParameter)
		}
		// Test response signing
		resp := httptest.NewRecorder()
		resp.HeaderMap.Set("Date", testDate)
		resp.HeaderMap.Set("Digest", testDigest)
		err = s.SignResponse(test.privKey, test.pubKeyId, resp)
		if test.expectErrorSigningResponse {
			if err != nil {
				// Skip rest of testing
				continue
			} else {
				t.Fatalf("%q: expected error, got nil", test.name)
			}
		}
		vals, ok = resp.HeaderMap[string(test.scheme)]
		if !ok {
			t.Fatalf("%q: not in header %s", test.name, test.scheme)
		}
		if len(vals) != 1 {
			t.Fatalf("%q: too many in header %s: %d", test.name, test.scheme, len(vals))
		}
		if p := toSignatureParameter(keyIdParameter, test.pubKeyId); !strings.Contains(vals[0], p) {
			t.Fatalf("%q: %s\ndoes not contain\n%s", test.name, vals[0], p)
		} else if p := toSignatureParameter(algorithmParameter, string(test.expectedAlgorithm)); !strings.Contains(vals[0], p) {
			t.Fatalf("%q: %s\ndoes not contain\n%s", test.name, vals[0], p)
		} else if p := toHeaderSignatureParameters(headersParameter, test.headers); !strings.Contains(vals[0], p) {
			t.Fatalf("%q: %s\ndoes not contain\n%s", test.name, vals[0], p)
		} else if !strings.Contains(vals[0], signatureParameter) {
			t.Fatalf("%q: %s\ndoes not contain\n%s", test.name, vals[0], signatureParameter)
		}
	}
}

func TestNewSignerRequestMissingHeaders(t *testing.T) {
	failingTests := []struct {
		name              string
		prefs             []Algorithm
		headers           []string
		scheme            SignatureScheme
		privKey           crypto.PrivateKey
		pubKeyId          string
		expectedAlgorithm Algorithm
	}{
		{
			name:              "wants digest",
			prefs:             []Algorithm{RSA_SHA512},
			headers:           []string{"Date", "Digest"},
			scheme:            Signature,
			privKey:           privKey,
			pubKeyId:          "pubKeyId",
			expectedAlgorithm: RSA_SHA512,
		},
	}
	for _, test := range failingTests {
		s, a, err := NewSigner(test.prefs, test.headers, test.scheme)
		if err != nil {
			t.Fatalf("%q: %s", test.name, err)
		}
		if a != test.expectedAlgorithm {
			t.Fatalf("%q: got %s, want %s", test.name, a, test.expectedAlgorithm)
		}
		req, err := http.NewRequest(testMethod, testUrl, nil)
		if err != nil {
			t.Fatalf("%q: %s", test.name, err)
		}
		req.Header.Set("Date", testDate)
		err = s.SignRequest(test.privKey, test.pubKeyId, req)
		if err == nil {
			t.Fatalf("%q: expect error but got nil", test.name)
		}
	}
}

func TestNewSignerResponseMissingHeaders(t *testing.T) {
	failingTests := []struct {
		name                       string
		prefs                      []Algorithm
		headers                    []string
		scheme                     SignatureScheme
		privKey                    crypto.PrivateKey
		pubKeyId                   string
		expectedAlgorithm          Algorithm
		expectErrorSigningResponse bool
	}{
		{
			name:              "want digest",
			prefs:             []Algorithm{RSA_SHA512},
			headers:           []string{"Date", "Digest"},
			scheme:            Signature,
			privKey:           privKey,
			pubKeyId:          "pubKeyId",
			expectedAlgorithm: RSA_SHA512,
		},
	}
	for _, test := range failingTests {
		s, a, err := NewSigner(test.prefs, test.headers, test.scheme)
		if err != nil {
			t.Fatalf("%q: %s", test.name, err)
		}
		if a != test.expectedAlgorithm {
			t.Fatalf("%q: got %s, want %s", test.name, a, test.expectedAlgorithm)
		}
		resp := httptest.NewRecorder()
		resp.HeaderMap.Set("Date", testDate)
		resp.HeaderMap.Set("Digest", testDigest)
		err = s.SignResponse(test.privKey, test.pubKeyId, resp)
		if err != nil {
			t.Fatalf("%q: expected error, got nil", test.name)
		}
	}
}

func TestNewVerifier(t *testing.T) {
	for _, test := range tests {
		// Prepare
		req, err := http.NewRequest(testMethod, testUrl, nil)
		if err != nil {
			t.Fatalf("%q: %s", test.name, err)
		}
		req.Header.Set("Date", testDate)
		req.Header.Set("Digest", testDigest)
		s, _, err := NewSigner(test.prefs, test.headers, test.scheme)
		if err != nil {
			t.Fatalf("%q: %s", test.name, err)
		}
		err = s.SignRequest(test.privKey, test.pubKeyId, req)
		if err != nil {
			t.Fatalf("%q: %s", test.name, err)
		}
		// Test verification
		v, err := NewVerifier(req)
		if err != nil {
			t.Fatalf("%q: %s", test.name, err)
		}
		if v.KeyId() != test.pubKeyId {
			t.Fatalf("%q: got %s, want %s", test.name, v.KeyId(), test.pubKeyId)
		}
		err = v.Verify(test.pubKey, test.expectedAlgorithm)
		if err != nil {
			t.Fatalf("%q: %s", test.name, err)
		}
	}
}

func TestNewResponseVerifier(t *testing.T) {
	for _, test := range tests {
		if test.expectErrorSigningResponse {
			continue
		}
		// Prepare
		resp := httptest.NewRecorder()
		resp.HeaderMap.Set("Date", testDate)
		resp.HeaderMap.Set("Digest", testDigest)
		s, _, err := NewSigner(test.prefs, test.headers, test.scheme)
		if err != nil {
			t.Fatalf("%q: %s", test.name, err)
		}
		err = s.SignResponse(test.privKey, test.pubKeyId, resp)
		if err != nil {
			t.Fatalf("%q: %s", test.name, err)
		}
		// Test verification
		v, err := NewResponseVerifier(resp.Result())
		if err != nil {
			t.Fatalf("%q: %s", test.name, err)
		}
		if v.KeyId() != test.pubKeyId {
			t.Fatalf("%q: got %s, want %s", test.name, v.KeyId(), test.pubKeyId)
		}
		err = v.Verify(test.pubKey, test.expectedAlgorithm)
		if err != nil {
			t.Fatalf("%q: %s", test.name, err)
		}
	}
}
