package httpsig

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"hash"
	doNotUseInProdCode "math/rand"
	"strings"
	"testing"
)

func readFullFromCrypto(b []byte) error {
	n := len(b)
	t := 0
	for t < n {
		d, err := rand.Reader.Read(b[t:])
		if d == 0 && err != nil {
			return err
		}
		t += d
	}
	return nil
}

func TestIsAvailable(t *testing.T) {
	tests := []struct {
		name        string
		algo        string
		expected    bool
		expectError bool
	}{
		{
			name:        md4String,
			algo:        md4String,
			expected:    false,
			expectError: true,
		},
		{
			name:        md5String,
			algo:        md5String,
			expected:    false,
			expectError: true,
		},
		{
			name:        sha1String,
			algo:        sha1String,
			expected:    false,
			expectError: true,
		},
		{
			name:        sha224String,
			algo:        sha224String,
			expected:    true,
			expectError: false,
		},
		{
			name:        sha256String,
			algo:        sha256String,
			expected:    true,
			expectError: false,
		},
		{
			name:        sha384String,
			algo:        sha384String,
			expected:    true,
			expectError: false,
		},
		{
			name:        sha512String,
			algo:        sha512String,
			expected:    true,
			expectError: false,
		},
		{
			name:        md5sha1String,
			algo:        md5sha1String,
			expected:    false,
			expectError: true,
		},
		{
			name:        ripemd160String,
			algo:        ripemd160String,
			expected:    true,
			expectError: false,
		},
		{
			name:        sha3_224String,
			algo:        sha3_224String,
			expected:    true,
			expectError: false,
		},
		{
			name:        sha3_256String,
			algo:        sha3_256String,
			expected:    true,
			expectError: false,
		},
		{
			name:        sha3_384String,
			algo:        sha3_384String,
			expected:    true,
			expectError: false,
		},
		{
			name:        sha3_512String,
			algo:        sha3_512String,
			expected:    true,
			expectError: false,
		},
		{
			name:        sha512_224String,
			algo:        sha512_224String,
			expected:    true,
			expectError: false,
		},
		{
			name:        sha512_256String,
			algo:        sha512_256String,
			expected:    true,
			expectError: false,
		},
		{
			name:        blake2s_256String,
			algo:        blake2s_256String,
			expected:    true,
			expectError: false,
		},
		{
			name:        blake2b_256String,
			algo:        blake2b_256String,
			expected:    true,
			expectError: false,
		},
		{
			name:        blake2b_384String,
			algo:        blake2b_384String,
			expected:    true,
			expectError: false,
		},
		{
			name:        blake2b_512String,
			algo:        blake2b_512String,
			expected:    true,
			expectError: false,
		},
	}
	for _, test := range tests {
		got, err := isAvailable(test.algo)
		gotErr := err != nil
		if got != test.expected {
			t.Fatalf("%q: got %v, want %v", test.name, got, test.expected)
		} else if gotErr != test.expectError {
			if test.expectError {
				t.Fatalf("%q: expected error, got: %s", test.name, err)
			} else {
				t.Fatalf("%q: expected no error, got: %s", test.name, err)
			}
		}
	}
}

func TestSignerFromString(t *testing.T) {
	tests := []struct {
		name        string
		input       Algorithm
		expectKind  crypto.Hash
		expectError bool
	}{
		{
			name:        "HMAC_SHA224",
			input:       HMAC_SHA224,
			expectError: true,
		},
		{
			name:        "HMAC_SHA256",
			input:       HMAC_SHA256,
			expectError: true,
		},
		{
			name:        "HMAC_SHA384",
			input:       HMAC_SHA384,
			expectError: true,
		},
		{
			name:        "HMAC_SHA512",
			input:       HMAC_SHA512,
			expectError: true,
		},
		{
			name:        "HMAC_RIPEMD160",
			input:       HMAC_RIPEMD160,
			expectError: true,
		},
		{
			name:        "HMAC_SHA3_224",
			input:       HMAC_SHA3_224,
			expectError: true,
		},
		{
			name:        "HMAC_SHA3_256",
			input:       HMAC_SHA3_256,
			expectError: true,
		},
		{
			name:        "HMAC_SHA3_384",
			input:       HMAC_SHA3_384,
			expectError: true,
		},
		{
			name:        "HMAC_SHA3_512",
			input:       HMAC_SHA3_512,
			expectError: true,
		},
		{
			name:        "HMAC_SHA512_224",
			input:       HMAC_SHA512_224,
			expectError: true,
		},
		{
			name:        "HMAC_SHA512_256",
			input:       HMAC_SHA512_256,
			expectError: true,
		},
		{
			name:        "HMAC_BLAKE2S_256",
			input:       HMAC_BLAKE2S_256,
			expectError: true,
		},
		{
			name:        "HMAC_BLAKE2B_256",
			input:       HMAC_BLAKE2B_256,
			expectError: true,
		},
		{
			name:        "HMAC_BLAKE2B_384",
			input:       HMAC_BLAKE2B_384,
			expectError: true,
		},
		{
			name:        "HMAC_BLAKE2B_512",
			input:       HMAC_BLAKE2B_512,
			expectError: true,
		},
		{
			name:        "BLAKE2S_256",
			input:       BLAKE2S_256,
			expectError: true,
		},
		{
			name:        "BLAKE2B_256",
			input:       BLAKE2B_256,
			expectError: true,
		},
		{
			name:        "BLAKE2B_384",
			input:       BLAKE2B_384,
			expectError: true,
		},
		{
			name:        "BLAKE2B_512",
			input:       BLAKE2B_512,
			expectError: true,
		},
		{
			name:       "RSA_SHA224",
			input:      RSA_SHA224,
			expectKind: crypto.SHA224,
		},
		{
			name:       "RSA_SHA256",
			input:      RSA_SHA256,
			expectKind: crypto.SHA256,
		},
		{
			name:       "RSA_SHA384",
			input:      RSA_SHA384,
			expectKind: crypto.SHA384,
		},
		{
			name:       "RSA_SHA512",
			input:      RSA_SHA512,
			expectKind: crypto.SHA512,
		},
		{
			name:       "RSA_RIPEMD160",
			input:      RSA_RIPEMD160,
			expectKind: crypto.RIPEMD160,
		},
		{
			name:       "rsa_SHA3_224",
			input:      rsa_SHA3_224,
			expectKind: crypto.SHA3_224,
		},
		{
			name:       "rsa_SHA3_256",
			input:      rsa_SHA3_256,
			expectKind: crypto.SHA3_256,
		},
		{
			name:       "rsa_SHA3_384",
			input:      rsa_SHA3_384,
			expectKind: crypto.SHA3_384,
		},
		{
			name:       "rsa_SHA3_512",
			input:      rsa_SHA3_512,
			expectKind: crypto.SHA3_512,
		},
		{
			name:       "rsa_SHA512_224",
			input:      rsa_SHA512_224,
			expectKind: crypto.SHA512_224,
		},
		{
			name:       "rsa_SHA512_256",
			input:      rsa_SHA512_256,
			expectKind: crypto.SHA512_256,
		},
		{
			name:       "rsa_BLAKE2S_256",
			input:      rsa_BLAKE2S_256,
			expectKind: crypto.BLAKE2s_256,
		},
		{
			name:       "rsa_BLAKE2B_256",
			input:      rsa_BLAKE2B_256,
			expectKind: crypto.BLAKE2b_256,
		},
		{
			name:       "rsa_BLAKE2B_384",
			input:      rsa_BLAKE2B_384,
			expectKind: crypto.BLAKE2b_384,
		},
		{
			name:       "rsa_BLAKE2B_512",
			input:      rsa_BLAKE2B_512,
			expectKind: crypto.BLAKE2b_512,
		},
	}
	for _, test := range tests {
		s, err := signerFromString(string(test.input))
		hasErr := err != nil
		if hasErr != test.expectError {
			if test.expectError {
				t.Fatalf("%q: expected error, got: %s", test.name, err)
			} else {
				t.Fatalf("%q: expected no error, got: %s", test.name, err)
			}
		} else if err == nil {
			want, ok := hashToDef[test.expectKind]
			if !ok {
				t.Fatalf("%q: Bad test setup, cannot find %q", test.name, test.expectKind)
			}
			if !strings.HasSuffix(s.String(), want.name) {
				t.Fatalf("%q: expected suffix %q, got %q", test.name, want.name, s.String())
			}
		}
	}
}

func TestMACerFromString(t *testing.T) {
	tests := []struct {
		name        string
		input       Algorithm
		expectKind  crypto.Hash
		expectError bool
	}{
		{
			name:       "HMAC_SHA224",
			input:      HMAC_SHA224,
			expectKind: crypto.SHA224,
		},
		{
			name:       "HMAC_SHA256",
			input:      HMAC_SHA256,
			expectKind: crypto.SHA256,
		},
		{
			name:       "HMAC_SHA384",
			input:      HMAC_SHA384,
			expectKind: crypto.SHA384,
		},
		{
			name:       "HMAC_SHA512",
			input:      HMAC_SHA512,
			expectKind: crypto.SHA512,
		},
		{
			name:       "HMAC_RIPEMD160",
			input:      HMAC_RIPEMD160,
			expectKind: crypto.RIPEMD160,
		},
		{
			name:       "HMAC_SHA3_224",
			input:      HMAC_SHA3_224,
			expectKind: crypto.SHA3_224,
		},
		{
			name:       "HMAC_SHA3_256",
			input:      HMAC_SHA3_256,
			expectKind: crypto.SHA3_256,
		},
		{
			name:       "HMAC_SHA3_384",
			input:      HMAC_SHA3_384,
			expectKind: crypto.SHA3_384,
		},
		{
			name:       "HMAC_SHA3_512",
			input:      HMAC_SHA3_512,
			expectKind: crypto.SHA3_512,
		},
		{
			name:       "HMAC_SHA512_224",
			input:      HMAC_SHA512_224,
			expectKind: crypto.SHA512_224,
		},
		{
			name:       "HMAC_SHA512_256",
			input:      HMAC_SHA512_256,
			expectKind: crypto.SHA512_256,
		},
		{
			name:       "HMAC_BLAKE2S_256",
			input:      HMAC_BLAKE2S_256,
			expectKind: crypto.BLAKE2s_256,
		},
		{
			name:       "HMAC_BLAKE2B_256",
			input:      HMAC_BLAKE2B_256,
			expectKind: crypto.BLAKE2b_256,
		},
		{
			name:       "HMAC_BLAKE2B_384",
			input:      HMAC_BLAKE2B_384,
			expectKind: crypto.BLAKE2b_384,
		},
		{
			name:       "HMAC_BLAKE2B_512",
			input:      HMAC_BLAKE2B_512,
			expectKind: crypto.BLAKE2b_512,
		},
		{
			name:       "BLAKE2S_256",
			input:      BLAKE2S_256,
			expectKind: crypto.BLAKE2s_256,
		},
		{
			name:       "BLAKE2B_256",
			input:      BLAKE2B_256,
			expectKind: crypto.BLAKE2b_256,
		},
		{
			name:       "BLAKE2B_384",
			input:      BLAKE2B_384,
			expectKind: crypto.BLAKE2b_384,
		},
		{
			name:       "BLAKE2B_512",
			input:      BLAKE2B_512,
			expectKind: crypto.BLAKE2b_512,
		},
		{
			name:        "RSA_SHA224",
			input:       RSA_SHA224,
			expectError: true,
		},
		{
			name:        "RSA_SHA256",
			input:       RSA_SHA256,
			expectError: true,
		},
		{
			name:        "RSA_SHA384",
			input:       RSA_SHA384,
			expectError: true,
		},
		{
			name:        "RSA_SHA512",
			input:       RSA_SHA512,
			expectError: true,
		},
		{
			name:        "RSA_RIPEMD160",
			input:       RSA_RIPEMD160,
			expectError: true,
		},
		{
			name:        "rsa_SHA3_224",
			input:       rsa_SHA3_224,
			expectError: true,
		},
		{
			name:        "rsa_SHA3_256",
			input:       rsa_SHA3_256,
			expectError: true,
		},
		{
			name:        "rsa_SHA3_384",
			input:       rsa_SHA3_384,
			expectError: true,
		},
		{
			name:        "rsa_SHA3_512",
			input:       rsa_SHA3_512,
			expectError: true,
		},
		{
			name:        "rsa_SHA512_224",
			input:       rsa_SHA512_224,
			expectError: true,
		},
		{
			name:        "rsa_SHA512_256",
			input:       rsa_SHA512_256,
			expectError: true,
		},
		{
			name:        "rsa_BLAKE2S_256",
			input:       rsa_BLAKE2S_256,
			expectError: true,
		},
		{
			name:        "rsa_BLAKE2B_256",
			input:       rsa_BLAKE2B_256,
			expectError: true,
		},
		{
			name:        "rsa_BLAKE2B_384",
			input:       rsa_BLAKE2B_384,
			expectError: true,
		},
		{
			name:        "rsa_BLAKE2B_512",
			input:       rsa_BLAKE2B_512,
			expectError: true,
		},
	}
	for _, test := range tests {
		m, err := macerFromString(string(test.input))
		hasErr := err != nil
		if hasErr != test.expectError {
			if test.expectError {
				t.Fatalf("%q: expected error, got: %s", test.name, err)
			} else {
				t.Fatalf("%q: expected no error, got: %s", test.name, err)
			}
		} else if err == nil {
			want, ok := hashToDef[test.expectKind]
			if !ok {
				t.Fatalf("%q: Bad test setup, cannot find %q", test.name, test.expectKind)
			}
			if !strings.HasSuffix(m.String(), want.name) {
				t.Fatalf("%q: expected suffix %q, got %q", test.name, want.name, m.String())
			}
		}
	}
}

func TestSignerSigns(t *testing.T) {
	tests := []struct {
		name                 string
		input                Algorithm
		inputCryptoHash      crypto.Hash
		expectRSAUnsupported bool
	}{
		{
			name:            "RSA_SHA224",
			input:           RSA_SHA224,
			inputCryptoHash: crypto.SHA224,
		},
		{
			name:            "RSA_SHA256",
			input:           RSA_SHA256,
			inputCryptoHash: crypto.SHA256,
		},
		{
			name:            "RSA_SHA384",
			input:           RSA_SHA384,
			inputCryptoHash: crypto.SHA384,
		},
		{
			name:            "RSA_SHA512",
			input:           RSA_SHA512,
			inputCryptoHash: crypto.SHA512,
		},
		{
			name:            "RSA_RIPEMD160",
			input:           RSA_RIPEMD160,
			inputCryptoHash: crypto.RIPEMD160,
		},
		{
			name:                 "rsa_SHA3_224",
			input:                rsa_SHA3_224,
			inputCryptoHash:      crypto.SHA3_224,
			expectRSAUnsupported: true,
		},
		{
			name:                 "rsa_SHA3_256",
			input:                rsa_SHA3_256,
			inputCryptoHash:      crypto.SHA3_256,
			expectRSAUnsupported: true,
		},
		{
			name:                 "rsa_SHA3_384",
			input:                rsa_SHA3_384,
			inputCryptoHash:      crypto.SHA3_384,
			expectRSAUnsupported: true,
		},
		{
			name:                 "rsa_SHA3_512",
			input:                rsa_SHA3_512,
			inputCryptoHash:      crypto.SHA3_512,
			expectRSAUnsupported: true,
		},
		{
			name:                 "rsa_SHA512_224",
			input:                rsa_SHA512_224,
			inputCryptoHash:      crypto.SHA512_224,
			expectRSAUnsupported: true,
		},
		{
			name:                 "rsa_SHA512_256",
			input:                rsa_SHA512_256,
			inputCryptoHash:      crypto.SHA512_256,
			expectRSAUnsupported: true,
		},
		{
			name:                 "rsa_BLAKE2S_256",
			input:                rsa_BLAKE2S_256,
			inputCryptoHash:      crypto.BLAKE2s_256,
			expectRSAUnsupported: true,
		},
		{
			name:                 "rsa_BLAKE2B_256",
			input:                rsa_BLAKE2B_256,
			inputCryptoHash:      crypto.BLAKE2b_256,
			expectRSAUnsupported: true,
		},
		{
			name:                 "rsa_BLAKE2B_384",
			input:                rsa_BLAKE2B_384,
			inputCryptoHash:      crypto.BLAKE2b_384,
			expectRSAUnsupported: true,
		},
		{
			name:                 "rsa_BLAKE2B_512",
			input:                rsa_BLAKE2B_512,
			inputCryptoHash:      crypto.BLAKE2b_512,
			expectRSAUnsupported: true,
		},
	}
	for _, test := range tests {
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("%q: Failed setup: %s", test.name, err)
		}
		sig := make([]byte, 65535)
		n, err := doNotUseInProdCode.Read(sig)
		if n != len(sig) {
			t.Fatalf("%q: Failed setup: %d bytes != %d bytes", test.name, n, len(sig))
		} else if err != nil {
			t.Fatalf("%q: Failed setup: %s", test.name, err)
		}
		s, err := signerFromString(string(test.input))
		if err != nil {
			t.Fatalf("%q: %s", test.name, err)
		}
		seed := doNotUseInProdCode.Int63()
		doNotUseThisKindOfRandInProdCodeTest := doNotUseInProdCode.New(doNotUseInProdCode.NewSource(seed))
		doNotUseThisKindOfRandInProdCodeTestVerify := doNotUseInProdCode.New(doNotUseInProdCode.NewSource(seed))
		actual, err := s.Sign(doNotUseThisKindOfRandInProdCodeTest, privKey, sig)
		hasErr := err != nil
		if test.expectRSAUnsupported != hasErr {
			if test.expectRSAUnsupported {
				t.Fatalf("%q: expected error, got: %s", test.name, err)
			} else {
				t.Fatalf("%q: expected no error, got: %s", test.name, err)
			}
		} else if !test.expectRSAUnsupported && err != nil {
			t.Fatalf("%q: %s", test.name, err)
		} else if test.expectRSAUnsupported {
			// Skip further testing -- just need to verify it is
			// unsupported.
			continue
		}
		testHash, err := hashToDef[test.inputCryptoHash].new(nil)
		if err != nil {
			t.Fatalf("%q: %s", test.name, err)
		}
		n, err = testHash.Write(sig)
		if n != len(sig) {
			t.Fatalf("%q: Failed setup: %d bytes != %d bytes", test.name, n, len(sig))
		} else if err != nil {
			t.Fatalf("%q: Failed setup: %s", test.name, err)
		}
		want, err := rsa.SignPKCS1v15(doNotUseThisKindOfRandInProdCodeTestVerify, privKey, test.inputCryptoHash, testHash.Sum(nil))
		if err != nil {
			t.Fatalf("%q: %s", test.name, err)
		}
		if len(actual) != len(want) {
			t.Fatalf("%q: len actual (%d) != len want (%d)", test.name, len(actual), len(want))
		}
		for i, v := range actual {
			if v != want[i] {
				t.Fatalf("%q: difference beginning at index %d:\nwant:   %v\nactual: %v", test.name, i, want, actual)
			}
		}
	}
}

func TestSignerVerifies(t *testing.T) {
	tests := []struct {
		name            string
		input           Algorithm
		inputCryptoHash crypto.Hash
	}{
		{
			name:            "RSA_SHA224",
			input:           RSA_SHA224,
			inputCryptoHash: crypto.SHA224,
		},
		{
			name:            "RSA_SHA256",
			input:           RSA_SHA256,
			inputCryptoHash: crypto.SHA256,
		},
		{
			name:            "RSA_SHA384",
			input:           RSA_SHA384,
			inputCryptoHash: crypto.SHA384,
		},
		{
			name:            "RSA_SHA512",
			input:           RSA_SHA512,
			inputCryptoHash: crypto.SHA512,
		},
		{
			name:            "RSA_RIPEMD160",
			input:           RSA_RIPEMD160,
			inputCryptoHash: crypto.RIPEMD160,
		},
	}
	for _, test := range tests {
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("%q: Failed setup: %s", test.name, err)
		}
		toHash := make([]byte, 65535)
		n, err := doNotUseInProdCode.Read(toHash)
		if n != len(toHash) {
			t.Fatalf("%q: Failed setup: %d bytes != %d bytes", test.name, n, len(toHash))
		} else if err != nil {
			t.Fatalf("%q: Failed setup: %s", test.name, err)
		}
		testHash, err := hashToDef[test.inputCryptoHash].new(nil)
		if err != nil {
			t.Fatalf("%q: %s", test.name, err)
		}
		n, err = testHash.Write(toHash)
		if n != len(toHash) {
			t.Fatalf("%q: Failed setup: %d bytes != %d bytes", test.name, n, len(toHash))
		} else if err != nil {
			t.Fatalf("%q: Failed setup: %s", test.name, err)
		}
		signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, test.inputCryptoHash, testHash.Sum(nil))
		if err != nil {
			t.Fatalf("%q: %s", test.name, err)
		}
		s, err := signerFromString(string(test.input))
		if err != nil {
			t.Fatalf("%q: %s", test.name, err)
		}
		err = s.Verify(privKey.Public(), toHash, signature)
		if err != nil {
			t.Fatalf("%q: %s", test.name, err)
		}
	}
}

func TestMACerSigns(t *testing.T) {
	tests := []struct {
		name            string
		input           Algorithm
		inputCryptoHash crypto.Hash
		isHMAC          bool
		keySize         int
	}{
		{
			name:            "HMAC_SHA224",
			input:           HMAC_SHA224,
			inputCryptoHash: crypto.SHA224,
			isHMAC:          true,
			keySize:         128,
		},
		{
			name:            "HMAC_SHA256",
			input:           HMAC_SHA256,
			inputCryptoHash: crypto.SHA256,
			isHMAC:          true,
			keySize:         128,
		},
		{
			name:            "HMAC_SHA384",
			input:           HMAC_SHA384,
			inputCryptoHash: crypto.SHA384,
			isHMAC:          true,
			keySize:         128,
		},
		{
			name:            "HMAC_SHA512",
			input:           HMAC_SHA512,
			inputCryptoHash: crypto.SHA512,
			isHMAC:          true,
			keySize:         128,
		},
		{
			name:            "HMAC_RIPEMD160",
			input:           HMAC_RIPEMD160,
			inputCryptoHash: crypto.RIPEMD160,
			isHMAC:          true,
			keySize:         128,
		},
		{
			name:            "HMAC_SHA3_224",
			input:           HMAC_SHA3_224,
			inputCryptoHash: crypto.SHA3_224,
			isHMAC:          true,
			keySize:         128,
		},
		{
			name:            "HMAC_SHA3_256",
			input:           HMAC_SHA3_256,
			inputCryptoHash: crypto.SHA3_256,
			isHMAC:          true,
			keySize:         128,
		},
		{
			name:            "HMAC_SHA3_384",
			input:           HMAC_SHA3_384,
			inputCryptoHash: crypto.SHA3_384,
			isHMAC:          true,
			keySize:         128,
		},
		{
			name:            "HMAC_SHA3_512",
			input:           HMAC_SHA3_512,
			inputCryptoHash: crypto.SHA3_512,
			isHMAC:          true,
			keySize:         128,
		},
		{
			name:            "HMAC_SHA512_224",
			input:           HMAC_SHA512_224,
			inputCryptoHash: crypto.SHA512_224,
			isHMAC:          true,
			keySize:         128,
		},
		{
			name:            "HMAC_SHA512_256",
			input:           HMAC_SHA512_256,
			inputCryptoHash: crypto.SHA512_256,
			isHMAC:          true,
			keySize:         128,
		},
		{
			name:            "HMAC_BLAKE2S_256",
			input:           HMAC_BLAKE2S_256,
			inputCryptoHash: crypto.BLAKE2s_256,
			isHMAC:          true,
			keySize:         128,
		},
		{
			name:            "HMAC_BLAKE2B_256",
			input:           HMAC_BLAKE2B_256,
			inputCryptoHash: crypto.BLAKE2b_256,
			isHMAC:          true,
			keySize:         128,
		},
		{
			name:            "HMAC_BLAKE2B_384",
			input:           HMAC_BLAKE2B_384,
			inputCryptoHash: crypto.BLAKE2b_384,
			isHMAC:          true,
			keySize:         128,
		},
		{
			name:            "HMAC_BLAKE2B_512",
			input:           HMAC_BLAKE2B_512,
			inputCryptoHash: crypto.BLAKE2b_512,
			isHMAC:          true,
			keySize:         128,
		},
		{
			name:            "BLAKE2S_256",
			input:           BLAKE2S_256,
			inputCryptoHash: crypto.BLAKE2s_256,
			keySize:         32,
		},
		{
			name:            "BLAKE2B_256",
			input:           BLAKE2B_256,
			inputCryptoHash: crypto.BLAKE2b_256,
			keySize:         64,
		},
		{
			name:            "BLAKE2B_384",
			input:           BLAKE2B_384,
			inputCryptoHash: crypto.BLAKE2b_384,
			keySize:         64,
		},
		{
			name:            "BLAKE2B_512",
			input:           BLAKE2B_512,
			inputCryptoHash: crypto.BLAKE2b_512,
			keySize:         64,
		},
	}
	for _, test := range tests {
		privKey := make([]byte, test.keySize)
		err := readFullFromCrypto(privKey)
		if err != nil {
			t.Fatalf("%q: Failed setup: %s", test.name, err)
		}
		sig := make([]byte, 65535)
		n, err := doNotUseInProdCode.Read(sig)
		if n != len(sig) {
			t.Fatalf("%q: Failed setup: %d bytes != %d bytes", test.name, n, len(sig))
		} else if err != nil {
			t.Fatalf("%q: Failed setup: %s", test.name, err)
		}
		m, err := macerFromString(string(test.input))
		if err != nil {
			t.Fatalf("%q: %s", test.name, err)
		}
		actual, err := m.Sign(sig, privKey)
		if err != nil {
			t.Fatalf("%q: %s", test.name, err)
		}
		var want []byte
		if test.isHMAC {
			hmacHash := hmac.New(func() hash.Hash {
				testHash, err := hashToDef[test.inputCryptoHash].new(nil)
				if err != nil {
					t.Fatalf("%q: %s", test.name, err)
				}
				return testHash
			}, privKey)
			n, err = hmacHash.Write(sig)
			if n != len(sig) {
				t.Fatalf("%q: Failed setup: %d bytes != %d bytes", test.name, n, len(sig))
			} else if err != nil {
				t.Fatalf("%q: Failed setup: %s", test.name, err)
			}
			want = hmacHash.Sum(nil)
		} else {
			testHash, err := hashToDef[test.inputCryptoHash].new(privKey)
			if err != nil {
				t.Fatalf("%q: %s", test.name, err)
			}
			n, err = testHash.Write(sig)
			if n != len(sig) {
				t.Fatalf("%q: Failed setup: %d bytes != %d bytes", test.name, n, len(sig))
			} else if err != nil {
				t.Fatalf("%q: Failed setup: %s", test.name, err)
			}
			want = testHash.Sum(nil)
		}
		if len(actual) != len(want) {
			t.Fatalf("%q: len actual (%d) != len want (%d)", test.name, len(actual), len(want))
		}
		for i, v := range actual {
			if v != want[i] {
				t.Fatalf("%q: difference beginning at index %d:\nwant:   %v\nactual: %v", test.name, i, want, actual)
			}
		}
	}
}

func TestMACerEquals(t *testing.T) {
	tests := []struct {
		name            string
		input           Algorithm
		inputCryptoHash crypto.Hash
		isHMAC          bool
		keySize         int
	}{
		{
			name:            "HMAC_SHA224",
			input:           HMAC_SHA224,
			inputCryptoHash: crypto.SHA224,
			isHMAC:          true,
			keySize:         128,
		},
		{
			name:            "HMAC_SHA256",
			input:           HMAC_SHA256,
			inputCryptoHash: crypto.SHA256,
			isHMAC:          true,
			keySize:         128,
		},
		{
			name:            "HMAC_SHA384",
			input:           HMAC_SHA384,
			inputCryptoHash: crypto.SHA384,
			isHMAC:          true,
			keySize:         128,
		},
		{
			name:            "HMAC_SHA512",
			input:           HMAC_SHA512,
			inputCryptoHash: crypto.SHA512,
			isHMAC:          true,
			keySize:         128,
		},
		{
			name:            "HMAC_RIPEMD160",
			input:           HMAC_RIPEMD160,
			inputCryptoHash: crypto.RIPEMD160,
			isHMAC:          true,
			keySize:         128,
		},
		{
			name:            "HMAC_SHA3_224",
			input:           HMAC_SHA3_224,
			inputCryptoHash: crypto.SHA3_224,
			isHMAC:          true,
			keySize:         128,
		},
		{
			name:            "HMAC_SHA3_256",
			input:           HMAC_SHA3_256,
			inputCryptoHash: crypto.SHA3_256,
			isHMAC:          true,
			keySize:         128,
		},
		{
			name:            "HMAC_SHA3_384",
			input:           HMAC_SHA3_384,
			inputCryptoHash: crypto.SHA3_384,
			isHMAC:          true,
			keySize:         128,
		},
		{
			name:            "HMAC_SHA3_512",
			input:           HMAC_SHA3_512,
			inputCryptoHash: crypto.SHA3_512,
			isHMAC:          true,
			keySize:         128,
		},
		{
			name:            "HMAC_SHA512_224",
			input:           HMAC_SHA512_224,
			inputCryptoHash: crypto.SHA512_224,
			isHMAC:          true,
			keySize:         128,
		},
		{
			name:            "HMAC_SHA512_256",
			input:           HMAC_SHA512_256,
			inputCryptoHash: crypto.SHA512_256,
			isHMAC:          true,
			keySize:         128,
		},
		{
			name:            "HMAC_BLAKE2S_256",
			input:           HMAC_BLAKE2S_256,
			inputCryptoHash: crypto.BLAKE2s_256,
			isHMAC:          true,
			keySize:         128,
		},
		{
			name:            "HMAC_BLAKE2B_256",
			input:           HMAC_BLAKE2B_256,
			inputCryptoHash: crypto.BLAKE2b_256,
			isHMAC:          true,
			keySize:         128,
		},
		{
			name:            "HMAC_BLAKE2B_384",
			input:           HMAC_BLAKE2B_384,
			inputCryptoHash: crypto.BLAKE2b_384,
			isHMAC:          true,
			keySize:         128,
		},
		{
			name:            "HMAC_BLAKE2B_512",
			input:           HMAC_BLAKE2B_512,
			inputCryptoHash: crypto.BLAKE2b_512,
			isHMAC:          true,
			keySize:         128,
		},
		{
			name:            "BLAKE2S_256",
			input:           BLAKE2S_256,
			inputCryptoHash: crypto.BLAKE2s_256,
			keySize:         32,
		},
		{
			name:            "BLAKE2B_256",
			input:           BLAKE2B_256,
			inputCryptoHash: crypto.BLAKE2b_256,
			keySize:         64,
		},
		{
			name:            "BLAKE2B_384",
			input:           BLAKE2B_384,
			inputCryptoHash: crypto.BLAKE2b_384,
			keySize:         64,
		},
		{
			name:            "BLAKE2B_512",
			input:           BLAKE2B_512,
			inputCryptoHash: crypto.BLAKE2b_512,
			keySize:         64,
		},
	}
	for _, test := range tests {
		privKey := make([]byte, test.keySize)
		err := readFullFromCrypto(privKey)
		if err != nil {
			t.Fatalf("%q: Failed setup: %s", test.name, err)
		}
		sig := make([]byte, 65535)
		n, err := doNotUseInProdCode.Read(sig)
		if n != len(sig) {
			t.Fatalf("%q: Failed setup: %d bytes != %d bytes", test.name, n, len(sig))
		} else if err != nil {
			t.Fatalf("%q: Failed setup: %s", test.name, err)
		}
		var actual []byte
		if test.isHMAC {
			hmacHash := hmac.New(func() hash.Hash {
				testHash, err := hashToDef[test.inputCryptoHash].new(nil)
				if err != nil {
					t.Fatalf("%q: %s", test.name, err)
				}
				return testHash
			}, privKey)
			n, err = hmacHash.Write(sig)
			if n != len(sig) {
				t.Fatalf("%q: Failed setup: %d bytes != %d bytes", test.name, n, len(sig))
			} else if err != nil {
				t.Fatalf("%q: Failed setup: %s", test.name, err)
			}
			actual = hmacHash.Sum(nil)
		} else {
			testHash, err := hashToDef[test.inputCryptoHash].new(privKey)
			if err != nil {
				t.Fatalf("%q: %s", test.name, err)
			}
			n, err = testHash.Write(sig)
			if n != len(sig) {
				t.Fatalf("%q: Failed setup: %d bytes != %d bytes", test.name, n, len(sig))
			} else if err != nil {
				t.Fatalf("%q: Failed setup: %s", test.name, err)
			}
			actual = testHash.Sum(nil)
		}
		m, err := macerFromString(string(test.input))
		if err != nil {
			t.Fatalf("%q: %s", test.name, err)
		}
		equal, err := m.Equal(sig, actual, privKey)
		if err != nil {
			t.Fatalf("%q: %s", test.name, err)
		} else if !equal {
			t.Fatalf("%q: signature is not verified", test.name)
		}
	}
}
