package httpsig

import (
	"bytes"
	"net/http"
	"testing"
)

func TestAddDigest(t *testing.T) {
	tests := []struct {
		name           string
		r              func() *http.Request
		algo           DigestAlgorithm
		body           []byte
		expectedDigest string
		expectError    bool
	}{
		{
			name: "adds sha256 digest",
			r: func() *http.Request {
				r, _ := http.NewRequest("POST", "example.com", nil)
				return r
			},
			algo:           "SHA-256",
			body:           []byte("johnny grab your gun"),
			expectedDigest: "SHA-256=RYiuVuVdRpU+BWcNUUg3sf0EbJjQ9LDj9tUqR546hhk=",
		},
		{
			name: "adds sha512 digest",
			r: func() *http.Request {
				r, _ := http.NewRequest("POST", "example.com", nil)
				return r
			},
			algo:           "SHA-512",
			body:           []byte("yours is the drill that will pierce the heavens"),
			expectedDigest: "SHA-512=bM0eBRnZkuiOTsejYNb/UpvFozde+Do1ZqlXfRTS39aGmoEzoXBpjmIIuznPslc3kaprUtI/VXH8/5HsD+thGg==",
		},
		{
			name: "digest already set",
			r: func() *http.Request {
				r, _ := http.NewRequest("POST", "example.com", nil)
				r.Header.Set("Digest", "oops")
				return r
			},
			algo:        "SHA-512",
			body:        []byte("did bob ewell fall on his knife"),
			expectError: true,
		},
		{
			name: "unknown/unsupported digest algorithm",
			r: func() *http.Request {
				r, _ := http.NewRequest("POST", "example.com", nil)
				return r
			},
			algo:        "MD5",
			body:        []byte("two times Cuchulainn almost drowned"),
			expectError: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test := test
			req := test.r()
			err := addDigest(req, test.algo, test.body)
			gotErr := err != nil
			if gotErr != test.expectError {
				if test.expectError {
					t.Fatalf("expected error, got: %s", err)
				} else {
					t.Fatalf("expected no error, got: %s", err)
				}
			} else if !gotErr {
				d := req.Header.Get("Digest")
				if d != test.expectedDigest {
					t.Fatalf("unexpected digest: want %s, got %s", test.expectedDigest, d)
				}
			}
		})
	}
}

func TestVerifyDigest(t *testing.T) {
	tests := []struct {
		name        string
		r           func() *http.Request
		body        []byte
		expectError bool
	}{
		{
			name: "verify sha256",
			r: func() *http.Request {
				r, _ := http.NewRequest("POST", "example.com", nil)
				r.Header.Set("Digest", "SHA-256=RYiuVuVdRpU+BWcNUUg3sf0EbJjQ9LDj9tUqR546hhk=")
				return r
			},
			body: []byte("johnny grab your gun"),
		},
		{
			name: "verify sha512",
			r: func() *http.Request {
				r, _ := http.NewRequest("POST", "example.com", nil)
				r.Header.Set("Digest", "SHA-512=bM0eBRnZkuiOTsejYNb/UpvFozde+Do1ZqlXfRTS39aGmoEzoXBpjmIIuznPslc3kaprUtI/VXH8/5HsD+thGg==")
				return r
			},
			body: []byte("yours is the drill that will pierce the heavens"),
		},
		{
			name: "no digest header",
			r: func() *http.Request {
				r, _ := http.NewRequest("POST", "example.com", nil)
				return r
			},
			body:        []byte("Yuji's gender is blue"),
			expectError: true,
		},
		{
			name: "malformed digest",
			r: func() *http.Request {
				r, _ := http.NewRequest("POST", "example.com", nil)
				r.Header.Set("Digest", "SHA-256am9obm55IGdyYWIgeW91ciBndW7jsMRCmPwcFJr79MiZb7kkJ65B5GSbk0yklZkbeFK4VQ==")
				return r
			},
			body:        []byte("Tochee and Ozzie BFFs forever"),
			expectError: true,
		},
		{
			name: "unsupported/unknown algo",
			r: func() *http.Request {
				r, _ := http.NewRequest("POST", "example.com", nil)
				r.Header.Set("Digest", "MD5=poo")
				return r
			},
			body:        []byte("what is a man? a miserable pile of secrets"),
			expectError: true,
		},
		{
			name: "bad digest",
			r: func() *http.Request {
				r, _ := http.NewRequest("POST", "example.com", nil)
				r.Header.Set("Digest", "SHA-256=bm9obm55IGdyYWIgeW91ciBndW7jsMRCmPwcFJr79MiZb7kkJ65B5GSbk0yklZkbeFK4VQ==")
				return r
			},
			body:        []byte("johnny grab your gun"),
			expectError: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test := test
			req := test.r()
			buf := bytes.NewBuffer(test.body)
			err := verifyDigest(req, buf)
			gotErr := err != nil
			if gotErr != test.expectError {
				if test.expectError {
					t.Fatalf("expected error, got: %s", err)
				} else {
					t.Fatalf("expected no error, got: %s", err)
				}
			}
		})
	}
}
