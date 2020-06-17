package httpsig

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ed25519"
)

const (
	testUrl     = "foo.net/bar/baz?q=test&r=ok"
	testUrlPath = "bar/baz"
	testDate    = "Tue, 07 Jun 2014 20:51:35 GMT"
	testDigest  = "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE="
	testMethod  = "GET"
)

type httpsigTest struct {
	name                       string
	prefs                      []Algorithm
	digestAlg                  DigestAlgorithm
	headers                    []string
	body                       []byte
	scheme                     SignatureScheme
	privKey                    crypto.PrivateKey
	pubKey                     crypto.PublicKey
	pubKeyId                   string
	expectedSignatureAlgorithm string
	expectedAlgorithm          Algorithm
	expectErrorSigningResponse bool
	expectRequestPath          bool
	expectedDigest             string
}

type ed25519PrivKey struct {
	Version          int
	ObjectIdentifier struct {
		ObjectIdentifier asn1.ObjectIdentifier
	}
	PrivateKey []byte
}

type ed25519PubKey struct {
	OBjectIdentifier struct {
		ObjectIdentifier asn1.ObjectIdentifier
	}
	PublicKey asn1.BitString
}

var (
	privKey               *rsa.PrivateKey
	macKey                []byte
	tests                 []httpsigTest
	testSpecRSAPrivateKey *rsa.PrivateKey
	testSpecRSAPublicKey  *rsa.PublicKey
	testEd25519PrivateKey ed25519.PrivateKey
	testEd25519PublicKey  ed25519.PublicKey
)

func init() {
	var err error
	privKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	pubEd25519Key, privEd25519Key, err := ed25519.GenerateKey(rand.Reader)
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
			name:                       "rsa signature",
			prefs:                      []Algorithm{RSA_SHA512},
			digestAlg:                  DigestSha256,
			headers:                    []string{"Date", "Digest"},
			scheme:                     Signature,
			privKey:                    privKey,
			pubKey:                     privKey.Public(),
			pubKeyId:                   "pubKeyId",
			expectedAlgorithm:          RSA_SHA512,
			expectedSignatureAlgorithm: "hs2019",
		},
		{
			name:                       "ed25519 signature",
			prefs:                      []Algorithm{ED25519},
			digestAlg:                  DigestSha512,
			headers:                    []string{"Date", "Digest"},
			scheme:                     Signature,
			privKey:                    privEd25519Key,
			pubKey:                     pubEd25519Key,
			pubKeyId:                   "pubKeyId",
			expectedAlgorithm:          ED25519,
			expectedSignatureAlgorithm: "hs2019",
		},
		{
			name:                       "digest on rsa signature",
			prefs:                      []Algorithm{RSA_SHA512},
			digestAlg:                  DigestSha256,
			headers:                    []string{"Date", "Digest"},
			body:                       []byte("Last night as I lay dreaming This strangest kind of feeling Revealed its secret meaning And now I know..."),
			scheme:                     Signature,
			privKey:                    privKey,
			pubKey:                     privKey.Public(),
			pubKeyId:                   "pubKeyId",
			expectedAlgorithm:          RSA_SHA512,
			expectedSignatureAlgorithm: "hs2019",
			expectedDigest:             "SHA-256=07PJQngqg8+BlomdI6zM7ieOxhINWI+iivJxBDSm3Dg=",
		},
		{
			name:                       "digest on ed25519 signature",
			prefs:                      []Algorithm{ED25519},
			digestAlg:                  DigestSha256,
			headers:                    []string{"Date", "Digest"},
			body:                       []byte("Last night as I lay dreaming This strangest kind of feeling Revealed its secret meaning And now I know..."),
			scheme:                     Signature,
			privKey:                    privEd25519Key,
			pubKey:                     pubEd25519Key,
			pubKeyId:                   "pubKeyId",
			expectedAlgorithm:          ED25519,
			expectedSignatureAlgorithm: "hs2019",
			expectedDigest:             "SHA-256=07PJQngqg8+BlomdI6zM7ieOxhINWI+iivJxBDSm3Dg=",
		},
		{
			name:                       "hmac signature",
			prefs:                      []Algorithm{HMAC_SHA256},
			digestAlg:                  DigestSha256,
			headers:                    []string{"Date", "Digest"},
			scheme:                     Signature,
			privKey:                    macKey,
			pubKey:                     macKey,
			pubKeyId:                   "pubKeyId",
			expectedAlgorithm:          HMAC_SHA256,
			expectedSignatureAlgorithm: "hs2019",
		},
		{
			name:                       "digest on hmac signature",
			prefs:                      []Algorithm{HMAC_SHA256},
			digestAlg:                  DigestSha256,
			headers:                    []string{"Date", "Digest"},
			body:                       []byte("I've never ever been to paradise I've never ever seen no angel's eyes You'll never ever let this magic die No matter where you are, you are my lucky star."),
			scheme:                     Signature,
			privKey:                    macKey,
			pubKey:                     macKey,
			pubKeyId:                   "pubKeyId",
			expectedAlgorithm:          HMAC_SHA256,
			expectedSignatureAlgorithm: "hs2019",
			expectedDigest:             "SHA-256=d0JoDjbDZRZF7/gUdgrazZCdKCJ9z9uUcMd6n1YKWRU=",
		},
		{
			name:                       "rsa authorization",
			prefs:                      []Algorithm{RSA_SHA512},
			digestAlg:                  DigestSha256,
			headers:                    []string{"Date", "Digest"},
			scheme:                     Authorization,
			privKey:                    privKey,
			pubKey:                     privKey.Public(),
			pubKeyId:                   "pubKeyId",
			expectedAlgorithm:          RSA_SHA512,
			expectedSignatureAlgorithm: "hs2019",
		},
		{
			name:                       "ed25519 authorization",
			prefs:                      []Algorithm{ED25519},
			digestAlg:                  DigestSha256,
			headers:                    []string{"Date", "Digest"},
			scheme:                     Authorization,
			privKey:                    privEd25519Key,
			pubKey:                     pubEd25519Key,
			pubKeyId:                   "pubKeyId",
			expectedAlgorithm:          ED25519,
			expectedSignatureAlgorithm: "hs2019",
		},
		{
			name:                       "hmac authorization",
			prefs:                      []Algorithm{HMAC_SHA256},
			digestAlg:                  DigestSha256,
			headers:                    []string{"Date", "Digest"},
			scheme:                     Authorization,
			privKey:                    macKey,
			pubKey:                     macKey,
			pubKeyId:                   "pubKeyId",
			expectedAlgorithm:          HMAC_SHA256,
			expectedSignatureAlgorithm: "hs2019",
		},
		{
			name:                       "default algo",
			digestAlg:                  DigestSha256,
			headers:                    []string{"Date", "Digest"},
			scheme:                     Signature,
			privKey:                    privKey,
			pubKey:                     privKey.Public(),
			pubKeyId:                   "pubKeyId",
			expectedAlgorithm:          RSA_SHA256,
			expectedSignatureAlgorithm: "hs2019",
		},
		{
			name:                       "default headers",
			prefs:                      []Algorithm{RSA_SHA512},
			digestAlg:                  DigestSha256,
			scheme:                     Signature,
			privKey:                    privKey,
			pubKey:                     privKey.Public(),
			pubKeyId:                   "pubKeyId",
			expectedAlgorithm:          RSA_SHA512,
			expectedSignatureAlgorithm: "hs2019",
		},
		{
			name:                       "different pub key id",
			prefs:                      []Algorithm{RSA_SHA512},
			digestAlg:                  DigestSha256,
			headers:                    []string{"Date", "Digest"},
			scheme:                     Signature,
			privKey:                    privKey,
			pubKey:                     privKey.Public(),
			pubKeyId:                   "i write code that sucks",
			expectedAlgorithm:          RSA_SHA512,
			expectedSignatureAlgorithm: "hs2019",
		},
		{
			name:                       "with request target",
			prefs:                      []Algorithm{RSA_SHA512},
			digestAlg:                  DigestSha256,
			headers:                    []string{"Date", "Digest", RequestTarget},
			scheme:                     Signature,
			privKey:                    privKey,
			pubKey:                     privKey.Public(),
			pubKeyId:                   "pubKeyId",
			expectedAlgorithm:          RSA_SHA512,
			expectedSignatureAlgorithm: "hs2019",
			expectErrorSigningResponse: true,
			expectRequestPath:          true,
		},
	}

	testSpecRSAPrivateKey, err = loadPrivateKey([]byte(testSpecPrivateKeyPEM))
	if err != nil {
		panic(err)
	}

	testSpecRSAPublicKey, err = loadPublicKey([]byte(testSpecPublicKeyPEM))
	if err != nil {
		panic(err)
	}

	testEd25519PrivateKey, err = loadEd25519PrivateKey([]byte(testEd25519PrivateKeyPEM))
	if err != nil {
		panic(err)
	}

	testEd25519PublicKey, err = loadEd25519PublicKey([]byte(testEd25519PublicKeyPEM))
	if err != nil {
		panic(err)
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

func TestSignerRequest(t *testing.T) {
	testFn := func(t *testing.T, test httpsigTest) {
		s, a, err := NewSigner(test.prefs, test.digestAlg, test.headers, test.scheme, 0)
		if err != nil {
			t.Fatalf("%s", err)
		}
		if a != test.expectedAlgorithm {
			t.Fatalf("got %s, want %s", a, test.expectedAlgorithm)
		}
		// Test request signing
		req, err := http.NewRequest(testMethod, testUrl, nil)
		if err != nil {
			t.Fatalf("%s", err)
		}
		req.Header.Set("Date", testDate)
		if test.body == nil {
			req.Header.Set("Digest", testDigest)
		}
		err = s.SignRequest(test.privKey, test.pubKeyId, req, test.body)
		if err != nil {
			t.Fatalf("%s", err)
		}
		vals, ok := req.Header[string(test.scheme)]
		if !ok {
			t.Fatalf("not in header %s", test.scheme)
		}
		if len(vals) != 1 {
			t.Fatalf("too many in header %s: %d", test.scheme, len(vals))
		}
		if p := toSignatureParameter(keyIdParameter, test.pubKeyId); !strings.Contains(vals[0], p) {
			t.Fatalf("%s\ndoes not contain\n%s", vals[0], p)
		} else if p := toSignatureParameter(algorithmParameter, string(test.expectedSignatureAlgorithm)); !strings.Contains(vals[0], p) {
			t.Fatalf("%s\ndoes not contain\n%s", vals[0], p)
		} else if p := toHeaderSignatureParameters(headersParameter, test.headers); !strings.Contains(vals[0], p) {
			t.Fatalf("%s\ndoes not contain\n%s", vals[0], p)
		} else if !strings.Contains(vals[0], signatureParameter) {
			t.Fatalf("%s\ndoes not contain\n%s", vals[0], signatureParameter)
		} else if test.body != nil && req.Header.Get("Digest") != test.expectedDigest {
			t.Fatalf("%s\ndoes not match\n%s", req.Header.Get("Digest"), test.expectedDigest)
		}
		// For schemes with an authScheme, enforce its is present and at the beginning
		if len(test.scheme.authScheme()) > 0 {
			if !strings.HasPrefix(vals[0], test.scheme.authScheme()) {
				t.Fatalf("%s\ndoes not start with\n%s", vals[0], test.scheme.authScheme())
			}
		}
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testFn(t, test)
		})
	}
}

func TestSignerResponse(t *testing.T) {
	testFn := func(t *testing.T, test httpsigTest) {
		s, _, err := NewSigner(test.prefs, test.digestAlg, test.headers, test.scheme, 0)
		// Test response signing
		resp := httptest.NewRecorder()
		resp.HeaderMap.Set("Date", testDate)
		if test.body == nil {
			resp.HeaderMap.Set("Digest", testDigest)
		}
		err = s.SignResponse(test.privKey, test.pubKeyId, resp, test.body)
		if test.expectErrorSigningResponse {
			if err != nil {
				// Skip rest of testing
				return
			} else {
				t.Fatalf("expected error, got nil")
			}
		}
		vals, ok := resp.HeaderMap[string(test.scheme)]
		if !ok {
			t.Fatalf("not in header %s", test.scheme)
		}
		if len(vals) != 1 {
			t.Fatalf("too many in header %s: %d", test.scheme, len(vals))
		}
		if p := toSignatureParameter(keyIdParameter, test.pubKeyId); !strings.Contains(vals[0], p) {
			t.Fatalf("%s\ndoes not contain\n%s", vals[0], p)
		} else if p := toSignatureParameter(algorithmParameter, string(test.expectedSignatureAlgorithm)); !strings.Contains(vals[0], p) {
			t.Fatalf("%s\ndoes not contain\n%s", vals[0], p)
		} else if p := toHeaderSignatureParameters(headersParameter, test.headers); !strings.Contains(vals[0], p) {
			t.Fatalf("%s\ndoes not contain\n%s", vals[0], p)
		} else if !strings.Contains(vals[0], signatureParameter) {
			t.Fatalf("%s\ndoes not contain\n%s", vals[0], signatureParameter)
		} else if test.body != nil && resp.Header().Get("Digest") != test.expectedDigest {
			t.Fatalf("%s\ndoes not match\n%s", resp.Header().Get("Digest"), test.expectedDigest)
		}
		// For schemes with an authScheme, enforce its is present and at the beginning
		if len(test.scheme.authScheme()) > 0 {
			if !strings.HasPrefix(vals[0], test.scheme.authScheme()) {
				t.Fatalf("%s\ndoes not start with\n%s", vals[0], test.scheme.authScheme())
			}
		}
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testFn(t, test)
		})
	}
}

func TestNewSignerRequestMissingHeaders(t *testing.T) {
	failingTests := []struct {
		name                       string
		prefs                      []Algorithm
		digestAlg                  DigestAlgorithm
		headers                    []string
		scheme                     SignatureScheme
		privKey                    crypto.PrivateKey
		pubKeyId                   string
		expectedAlgorithm          Algorithm
		expectedSignatureAlgorithm string
	}{
		{
			name:                       "wants digest",
			prefs:                      []Algorithm{RSA_SHA512},
			digestAlg:                  DigestSha256,
			headers:                    []string{"Date", "Digest"},
			scheme:                     Signature,
			privKey:                    privKey,
			pubKeyId:                   "pubKeyId",
			expectedSignatureAlgorithm: "hs2019",
			expectedAlgorithm:          RSA_SHA512,
		},
	}
	for _, test := range failingTests {
		t.Run(test.name, func(t *testing.T) {
			test := test
			s, a, err := NewSigner(test.prefs, test.digestAlg, test.headers, test.scheme, 0)
			if err != nil {
				t.Fatalf("%s", err)
			}
			if a != test.expectedAlgorithm {
				t.Fatalf("got %s, want %s", a, test.expectedAlgorithm)
			}
			req, err := http.NewRequest(testMethod, testUrl, nil)
			if err != nil {
				t.Fatalf("%s", err)
			}
			req.Header.Set("Date", testDate)
			err = s.SignRequest(test.privKey, test.pubKeyId, req, nil)
			if err == nil {
				t.Fatalf("expect error but got nil")
			}
		})
	}
}

func TestNewSignerResponseMissingHeaders(t *testing.T) {
	failingTests := []struct {
		name                       string
		prefs                      []Algorithm
		digestAlg                  DigestAlgorithm
		headers                    []string
		scheme                     SignatureScheme
		privKey                    crypto.PrivateKey
		pubKeyId                   string
		expectedAlgorithm          Algorithm
		expectErrorSigningResponse bool
		expectedSignatureAlgorithm string
	}{
		{
			name:                       "want digest",
			prefs:                      []Algorithm{RSA_SHA512},
			digestAlg:                  DigestSha256,
			headers:                    []string{"Date", "Digest"},
			scheme:                     Signature,
			privKey:                    privKey,
			pubKeyId:                   "pubKeyId",
			expectedSignatureAlgorithm: "hs2019",
			expectedAlgorithm:          RSA_SHA512,
		},
	}
	for _, test := range failingTests {
		t.Run(test.name, func(t *testing.T) {
			test := test
			s, a, err := NewSigner(test.prefs, test.digestAlg, test.headers, test.scheme, 0)
			if err != nil {
				t.Fatalf("%s", err)
			}
			if a != test.expectedAlgorithm {
				t.Fatalf("got %s, want %s", a, test.expectedAlgorithm)
			}
			resp := httptest.NewRecorder()
			resp.HeaderMap.Set("Date", testDate)
			resp.HeaderMap.Set("Digest", testDigest)
			err = s.SignResponse(test.privKey, test.pubKeyId, resp, nil)
			if err != nil {
				t.Fatalf("expected error, got nil")
			}
		})
	}
}

func TestNewVerifier(t *testing.T) {
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test := test
			// Prepare
			req, err := http.NewRequest(testMethod, testUrl, nil)
			if err != nil {
				t.Fatalf("%s", err)
			}
			req.Header.Set("Date", testDate)
			if test.body == nil {
				req.Header.Set("Digest", testDigest)
			}
			s, _, err := NewSigner(test.prefs, test.digestAlg, test.headers, test.scheme, 0)
			if err != nil {
				t.Fatalf("%s", err)
			}
			err = s.SignRequest(test.privKey, test.pubKeyId, req, test.body)
			if err != nil {
				t.Fatalf("%s", err)
			}
			// Test verification
			v, err := NewVerifier(req)
			if err != nil {
				t.Fatalf("%s", err)
			}
			if v.KeyId() != test.pubKeyId {
				t.Fatalf("got %s, want %s", v.KeyId(), test.pubKeyId)
			}
			err = v.Verify(test.pubKey, test.expectedAlgorithm)
			if err != nil {
				t.Fatalf("%s", err)
			}
		})
	}
}

func TestNewResponseVerifier(t *testing.T) {
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test := test
			if test.expectErrorSigningResponse {
				return
			}
			// Prepare
			resp := httptest.NewRecorder()
			resp.HeaderMap.Set("Date", testDate)
			if test.body == nil {
				resp.HeaderMap.Set("Digest", testDigest)
			}
			s, _, err := NewSigner(test.prefs, test.digestAlg, test.headers, test.scheme, 0)
			if err != nil {
				t.Fatalf("%s", err)
			}
			err = s.SignResponse(test.privKey, test.pubKeyId, resp, test.body)
			if err != nil {
				t.Fatalf("%s", err)
			}
			// Test verification
			v, err := NewResponseVerifier(resp.Result())
			if err != nil {
				t.Fatalf("%s", err)
			}
			if v.KeyId() != test.pubKeyId {
				t.Fatalf("got %s, want %s", v.KeyId(), test.pubKeyId)
			}
			err = v.Verify(test.pubKey, test.expectedAlgorithm)
			if err != nil {
				t.Fatalf("%s", err)
			}
		})
	}
}

// Test_Signing_HTTP_Messages_AppendixC implement tests from Appendix C
// in the http signatures specification:
// https://tools.ietf.org/html/draft-cavage-http-signatures-10#appendix-C
func Test_Signing_HTTP_Messages_AppendixC(t *testing.T) {
	specTests := []struct {
		name              string
		headers           []string
		expectedSignature string
	}{
		{
			name:    "C.1.  Default Test",
			headers: []string{},
			// NOTE: In the Appendix C tests, the following is NOT included:
			//    `headers="date"`
			// But httpsig will ALWAYS explicitly list the headers used in its
			// signature. Hence, I have introduced it here.
			//
			// NOTE: In verification, if there are no headers listed, the
			// default headers (date) are indeed used as required by the
			// specification.
			expectedSignature: `Authorization: Signature keyId="Test",algorithm="hs2019",headers="date",signature="SjWJWbWN7i0wzBvtPl8rbASWz5xQW6mcJmn+ibttBqtifLN7Sazz6m79cNfwwb8DMJ5cou1s7uEGKKCs+FLEEaDV5lp7q25WqS+lavg7T8hc0GppauB6hbgEKTwblDHYGEtbGmtdHgVCk9SuS13F0hZ8FD0k/5OxEPXe5WozsbM="`,
		},
		{
			name:              "C.2.  Basic Test",
			headers:           []string{"(request-target)", "host", "date"},
			expectedSignature: `Authorization: Signature keyId="Test",algorithm="hs2019",headers="(request-target) host date",signature="qdx+H7PHHDZgy4y/Ahn9Tny9V3GP6YgBPyUXMmoxWtLbHpUnXS2mg2+SbrQDMCJypxBLSPQR2aAjn7ndmw2iicw3HMbe8VfEdKFYRqzic+efkb3nndiv/x1xSHDJWeSWkx3ButlYSuBskLu6kd9Fswtemr3lgdDEmn04swr2Os0="`,
		},
		{
			name:              "C.3.  All Headers Test",
			headers:           []string{"(request-target)", "host", "date", "content-type", "digest", "content-length"},
			expectedSignature: `Authorization: Signature keyId="Test",algorithm="hs2019",headers="(request-target) host date content-type digest content-length",signature="vSdrb+dS3EceC9bcwHSo4MlyKS59iFIrhgYkz8+oVLEEzmYZZvRs8rgOp+63LEM3v+MFHB32NfpB2bEKBIvB1q52LaEUHFv120V01IL+TAD48XaERZFukWgHoBTLMhYS2Gb51gWxpeIq8knRmPnYePbF5MOkR0Zkly4zKH7s1dE="`,
		},
	}

	for _, test := range specTests {
		t.Run(test.name, func(t *testing.T) {
			test := test
			r, err := http.NewRequest("POST", "http://example.com/foo?param=value&pet=dog", bytes.NewBuffer([]byte(testSpecBody)))
			if err != nil {
				t.Fatalf("error creating request: %s", err)
			}

			r.Header["Date"] = []string{testSpecDate}
			r.Header["Host"] = []string{r.URL.Host}
			r.Header["Content-Length"] = []string{strconv.Itoa(len(testSpecBody))}
			r.Header["Content-Type"] = []string{"application/json"}
			setDigest(r)

			s, _, err := NewSigner([]Algorithm{RSA_SHA256}, DigestSha256, test.headers, Authorization, 0)
			if err != nil {
				t.Fatalf("error creating signer: %s", err)
			}

			if err := s.SignRequest(testSpecRSAPrivateKey, "Test", r, nil); err != nil {
				t.Fatalf("error signing request: %s", err)
			}

			expectedAuth := test.expectedSignature
			gotAuth := fmt.Sprintf("Authorization: %s", r.Header["Authorization"][0])
			if gotAuth != expectedAuth {
				t.Errorf("Signature string mismatch\nGot: %s\nWant: %s", gotAuth, expectedAuth)
			}
		})
	}
}

func TestSigningEd25519(t *testing.T) {
	specTests := []struct {
		name              string
		headers           []string
		expectedSignature string
	}{
		{
			name:    "Default Test",
			headers: []string{},
			// NOTE: In the Appendix C tests, the following is NOT included:
			//    `headers="date"`
			// But httpsig will ALWAYS explicitly list the headers used in its
			// signature. Hence, I have introduced it here.
			//
			// NOTE: In verification, if there are no headers listed, the
			// default headers (date) are indeed used as required by the
			// specification.
			expectedSignature: `Authorization: Signature keyId="Test",algorithm="hs2019",headers="date",signature="6G9bNnUfph4pnl3j8l4UTcSPJVg6r4tM73eWFAn+w4IdIi8yzzZs65QlgM31lAuVCRKlqMzME9VGgMt16nU1AQ=="`,
		},
		{
			name:              "Basic Test",
			headers:           []string{"(request-target)", "host", "date"},
			expectedSignature: `Authorization: Signature keyId="Test",algorithm="hs2019",headers="(request-target) host date",signature="upsoNpw5oJTD3lTIQHEnDGWTaKmlT7o2c9Lz3kqy2UTwOEpEop3Sd7F/K2bYD2lQ4AH1HRyvC4/9AcKgNBg1AA=="`,
		},
		{
			name:              "All Headers Test",
			headers:           []string{"(request-target)", "host", "date", "content-type", "digest", "content-length"},
			expectedSignature: `Authorization: Signature keyId="Test",algorithm="hs2019",headers="(request-target) host date content-type digest content-length",signature="UkxhZl0W5/xcuCIP5xOPv4V6rX0TmaV2lmrYYGWauKhdFHihpW80tCqTNFDhyD+nYeGNCRSFRHmDS0bGm0PVAg=="`,
		},
	}

	for _, test := range specTests {
		t.Run(test.name, func(t *testing.T) {
			test := test
			r, err := http.NewRequest("POST", "http://example.com/foo?param=value&pet=dog", bytes.NewBuffer([]byte(testSpecBody)))
			if err != nil {
				t.Fatalf("error creating request: %s", err)
			}

			r.Header["Date"] = []string{testSpecDate}
			r.Header["Host"] = []string{r.URL.Host}
			r.Header["Content-Length"] = []string{strconv.Itoa(len(testSpecBody))}
			r.Header["Content-Type"] = []string{"application/json"}
			setDigest(r)

			s, _, err := NewSigner([]Algorithm{ED25519}, DigestSha256, test.headers, Authorization, 0)
			if err != nil {
				t.Fatalf("error creating signer: %s", err)
			}

			if err := s.SignRequest(testEd25519PrivateKey, "Test", r, nil); err != nil {
				t.Fatalf("error signing request: %s", err)
			}

			expectedAuth := test.expectedSignature
			gotAuth := fmt.Sprintf("Authorization: %s", r.Header["Authorization"][0])
			if gotAuth != expectedAuth {
				t.Errorf("Signature string mismatch\nGot: %s\nWant: %s", gotAuth, expectedAuth)
			}
		})
	}
}

// Test_Verifying_HTTP_Messages_AppendixC implement tests from Appendix C
// in the http signatures specification:
// https://tools.ietf.org/html/draft-cavage-http-signatures-10#appendix-C
func Test_Verifying_HTTP_Messages_AppendixC(t *testing.T) {
	specTests := []struct {
		name      string
		headers   []string
		signature string
	}{
		{
			name:      "C.1.  Default Test",
			headers:   []string{},
			signature: `Signature keyId="Test",algorithm="rsa-sha256",signature="SjWJWbWN7i0wzBvtPl8rbASWz5xQW6mcJmn+ibttBqtifLN7Sazz6m79cNfwwb8DMJ5cou1s7uEGKKCs+FLEEaDV5lp7q25WqS+lavg7T8hc0GppauB6hbgEKTwblDHYGEtbGmtdHgVCk9SuS13F0hZ8FD0k/5OxEPXe5WozsbM="`,
		},
		{
			name:      "C.2.  Basic Test",
			headers:   []string{"(request-target)", "host", "date"},
			signature: `Signature keyId="Test",algorithm="rsa-sha256",headers="(request-target) host date",signature="qdx+H7PHHDZgy4y/Ahn9Tny9V3GP6YgBPyUXMmoxWtLbHpUnXS2mg2+SbrQDMCJypxBLSPQR2aAjn7ndmw2iicw3HMbe8VfEdKFYRqzic+efkb3nndiv/x1xSHDJWeSWkx3ButlYSuBskLu6kd9Fswtemr3lgdDEmn04swr2Os0="`,
		},
		{
			name:      "C.3.  All Headers Test",
			headers:   []string{"(request-target)", "host", "date", "content-type", "digest", "content-length"},
			signature: `Signature keyId="Test",algorithm="rsa-sha256",headers="(request-target) host date content-type digest content-length",signature="vSdrb+dS3EceC9bcwHSo4MlyKS59iFIrhgYkz8+oVLEEzmYZZvRs8rgOp+63LEM3v+MFHB32NfpB2bEKBIvB1q52LaEUHFv120V01IL+TAD48XaERZFukWgHoBTLMhYS2Gb51gWxpeIq8knRmPnYePbF5MOkR0Zkly4zKH7s1dE="`,
		},
	}

	for _, test := range specTests {
		t.Run(test.name, func(t *testing.T) {
			test := test
			r, err := http.NewRequest("POST", "http://example.com/foo?param=value&pet=dog", bytes.NewBuffer([]byte(testSpecBody)))
			if err != nil {
				t.Fatalf("error creating request: %s", err)
			}

			r.Header["Date"] = []string{testSpecDate}
			r.Header["Host"] = []string{r.URL.Host}
			r.Header["Content-Length"] = []string{strconv.Itoa(len(testSpecBody))}
			r.Header["Content-Type"] = []string{"application/json"}
			setDigest(r)
			r.Header["Authorization"] = []string{test.signature}

			v, err := NewVerifier(r)
			if err != nil {
				t.Fatalf("error creating verifier: %s", err)
			}

			if "Test" != v.KeyId() {
				t.Errorf("KeyId mismatch\nGot: %s\nWant: Test", v.KeyId())
			}
			if err := v.Verify(testSpecRSAPublicKey, RSA_SHA256); err != nil {
				t.Errorf("Verification failure: %s", err)
			}
		})
	}
}

func TestVerifyingEd25519(t *testing.T) {
	specTests := []struct {
		name      string
		headers   []string
		signature string
	}{
		{
			name:      "Default Test",
			headers:   []string{},
			signature: `Signature keyId="Test",algorithm="hs2019",headers="date",signature="6G9bNnUfph4pnl3j8l4UTcSPJVg6r4tM73eWFAn+w4IdIi8yzzZs65QlgM31lAuVCRKlqMzME9VGgMt16nU1AQ=="`,
		},
		{
			name:      "Basic Test",
			headers:   []string{"(request-target)", "host", "date"},
			signature: `Signature keyId="Test",algorithm="hs2019",headers="(request-target) host date",signature="upsoNpw5oJTD3lTIQHEnDGWTaKmlT7o2c9Lz3kqy2UTwOEpEop3Sd7F/K2bYD2lQ4AH1HRyvC4/9AcKgNBg1AA=="`,
		},
		{
			name:      "All Headers Test",
			headers:   []string{"(request-target)", "host", "date", "content-type", "digest", "content-length"},
			signature: `Signature keyId="Test",algorithm="hs2019",headers="(request-target) host date content-type digest content-length",signature="UkxhZl0W5/xcuCIP5xOPv4V6rX0TmaV2lmrYYGWauKhdFHihpW80tCqTNFDhyD+nYeGNCRSFRHmDS0bGm0PVAg=="`,
		},
	}

	for _, test := range specTests {
		t.Run(test.name, func(t *testing.T) {
			test := test
			r, err := http.NewRequest("POST", "http://example.com/foo?param=value&pet=dog", bytes.NewBuffer([]byte(testSpecBody)))
			if err != nil {
				t.Fatalf("error creating request: %s", err)
			}

			r.Header["Date"] = []string{testSpecDate}
			r.Header["Host"] = []string{r.URL.Host}
			r.Header["Content-Length"] = []string{strconv.Itoa(len(testSpecBody))}
			r.Header["Content-Type"] = []string{"application/json"}
			setDigest(r)
			r.Header["Authorization"] = []string{test.signature}

			v, err := NewVerifier(r)
			if err != nil {
				t.Fatalf("error creating verifier: %s", err)
			}

			if "Test" != v.KeyId() {
				t.Errorf("KeyId mismatch\nGot: %s\nWant: Test", v.KeyId())
			}
			if err := v.Verify(testEd25519PublicKey, ED25519); err != nil {
				t.Errorf("Verification failure: %s", err)
			}
		})
	}
}

func loadPrivateKey(keyData []byte) (*rsa.PrivateKey, error) {
	pem, _ := pem.Decode(keyData)
	if pem.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("RSA private key is of the wrong type: %s", pem.Type)
	}

	return x509.ParsePKCS1PrivateKey(pem.Bytes)
}

// taken from https://blainsmith.com/articles/signing-jwts-with-gos-crypto-ed25519/
func loadEd25519PrivateKey(keyData []byte) (ed25519.PrivateKey, error) {
	var block *pem.Block
	block, _ = pem.Decode(keyData)

	var asn1PrivKey ed25519PrivKey
	asn1.Unmarshal(block.Bytes, &asn1PrivKey)

	// [2:] is skipping the byte for TAG and the byte for LEN
	// see also https://tools.ietf.org/html/draft-ietf-curdle-pkix-10#section-10.3
	return ed25519.NewKeyFromSeed(asn1PrivKey.PrivateKey[2:]), nil
}

func loadPublicKey(keyData []byte) (*rsa.PublicKey, error) {
	pem, _ := pem.Decode(keyData)
	if pem.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("public key is of the wrong type: %s", pem.Type)
	}

	key, err := x509.ParsePKIXPublicKey(pem.Bytes)
	if err != nil {
		return nil, err
	}

	return key.(*rsa.PublicKey), nil
}

// taken from https://blainsmith.com/articles/signing-jwts-with-gos-crypto-ed25519/
func loadEd25519PublicKey(keyData []byte) (ed25519.PublicKey, error) {
	var block *pem.Block
	block, _ = pem.Decode(keyData)

	var asn1PubKey ed25519PubKey
	asn1.Unmarshal(block.Bytes, &asn1PubKey)

	return ed25519.PublicKey(asn1PubKey.PublicKey.Bytes), nil
}

func setDigest(r *http.Request) ([]byte, error) {
	var bodyBytes []byte
	if _, ok := r.Header["Digest"]; !ok {
		body := ""
		if r.Body != nil {
			var err error
			bodyBytes, err = ioutil.ReadAll(r.Body)
			if err != nil {
				return nil, fmt.Errorf("error reading body. %v", err)
			}

			// And now set a new body, which will simulate the same data we read:
			r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
			body = string(bodyBytes)
		}

		d := sha256.Sum256([]byte(body))
		r.Header["Digest"] = []string{fmt.Sprintf("SHA-256=%s", base64.StdEncoding.EncodeToString(d[:]))}
	}

	return bodyBytes, nil
}

const testSpecBody = `{"hello": "world"}`

const testSpecDate = `Sun, 05 Jan 2014 21:31:40 GMT`

const testSpecPrivateKeyPEM = `-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDCFENGw33yGihy92pDjZQhl0C36rPJj+CvfSC8+q28hxA161QF
NUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6Z4UMR7EOcpfdUE9Hf3m/hs+F
UR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJwoYi+1hqp1fIekaxsyQIDAQAB
AoGBAJR8ZkCUvx5kzv+utdl7T5MnordT1TvoXXJGXK7ZZ+UuvMNUCdN2QPc4sBiA
QWvLw1cSKt5DsKZ8UETpYPy8pPYnnDEz2dDYiaew9+xEpubyeW2oH4Zx71wqBtOK
kqwrXa/pzdpiucRRjk6vE6YY7EBBs/g7uanVpGibOVAEsqH1AkEA7DkjVH28WDUg
f1nqvfn2Kj6CT7nIcE3jGJsZZ7zlZmBmHFDONMLUrXR/Zm3pR5m0tCmBqa5RK95u
412jt1dPIwJBANJT3v8pnkth48bQo/fKel6uEYyboRtA5/uHuHkZ6FQF7OUkGogc
mSJluOdc5t6hI1VsLn0QZEjQZMEOWr+wKSMCQQCC4kXJEsHAve77oP6HtG/IiEn7
kpyUXRNvFsDE0czpJJBvL/aRFUJxuRK91jhjC68sA7NsKMGg5OXb5I5Jj36xAkEA
gIT7aFOYBFwGgQAQkWNKLvySgKbAZRTeLBacpHMuQdl1DfdntvAyqpAZ0lY0RKmW
G6aFKaqQfOXKCyWoUiVknQJAXrlgySFci/2ueKlIE1QqIiLSZ8V8OlpFLRnb1pzI
7U1yQXnTAEFYM560yJlzUpOb1V4cScGd365tiSMvxLOvTA==
-----END RSA PRIVATE KEY-----`

const testSpecPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCFENGw33yGihy92pDjZQhl0C3
6rPJj+CvfSC8+q28hxA161QFNUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6
Z4UMR7EOcpfdUE9Hf3m/hs+FUR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJw
oYi+1hqp1fIekaxsyQIDAQAB
-----END PUBLIC KEY-----`

const testEd25519PrivateKeyPEM = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIAP+PK4NtdzCe04sbtwBvf9IShlky298SMMBqkCCToHn
-----END PRIVATE KEY-----`

const testEd25519PublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAhyP+7zpNCsr7/ipGJjK0zVszTEQ5tooyX3VLAnBSc1c=
-----END PUBLIC KEY-----`
