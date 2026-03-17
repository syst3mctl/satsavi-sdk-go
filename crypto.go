package satsavi

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
)

// CryptoResult contains the encrypted data and metadata (ciphertext and IV)
type CryptoResult struct {
	CiphertextB64 string
	IVB64         string
}

// Encrypt encrypts plainText using AES-GCM (256-bit)
func Encrypt(plainText []byte, key []byte) (*CryptoResult, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, plainText, nil)

	return &CryptoResult{
		CiphertextB64: base64.StdEncoding.EncodeToString(ciphertext),
		IVB64:         base64.StdEncoding.EncodeToString(nonce),
	}, nil
}

// Decrypt decrypts ciphertext using AES-GCM (256-bit)
func Decrypt(ciphertextB64, ivB64 string, key []byte) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", err
	}

	nonce, err := base64.StdEncoding.DecodeString(ivB64)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// Generate256BitKey generates a random 32-byte key for AES-256
func Generate256BitKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %v", err)
	}
	return key, nil
}

// WrapKeyRSA wraps an AES key using an RSA public key with OAEP (SHA256)
func WrapKeyRSA(rawKey []byte, publicKeyPEM string) (string, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return "", fmt.Errorf("failed to parse PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse public key: %v", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("not an RSA public key")
	}

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPub, rawKey, nil)
	if err != nil {
		return "", fmt.Errorf("RSA wrapping failed: %v", err)
	}

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}
