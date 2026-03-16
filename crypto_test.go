package satsavi

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	key, _ := Generate256BitKey()
	plaintext := "this is a secret message"

	// Encrypt
	res, err := Encrypt([]byte(plaintext), key)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	if res.CiphertextB64 == "" || res.IVB64 == "" {
		t.Errorf("Empty result from encryption")
	}

	// Decrypt
	decrypted, err := Decrypt(res.CiphertextB64, res.IVB64, key)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("Decrypted text %q does not match original %q", decrypted, plaintext)
	}
}

func TestRSAWrapping(t *testing.T) {
	// 1. Generate a test RSA key pair
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})

	// 2. Test wrapping
	aesKey, _ := Generate256BitKey()
	wrapped, err := WrapKeyRSA(aesKey, string(pubPEM))
	if err != nil {
		t.Fatalf("Wrapping failed: %v", err)
	}

	if wrapped == "" {
		t.Fatal("Wrapped key is empty")
	}
}
