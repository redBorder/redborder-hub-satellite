package common

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

// GenerateAndSaveEd25519Keys generates a new Ed25519 key pair and saves them to the specified files in PEM format.
func GenerateAndSaveEd25519Keys(privPath, pubPath string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// 1. Save Private Key (PKCS#8 PEM)
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	privBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	}
	privFile, err := os.OpenFile(privPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open private key file: %w", err)
	}
	defer privFile.Close()
	if err := pem.Encode(privFile, privBlock); err != nil {
		return nil, nil, fmt.Errorf("failed to encode private key PEM: %w", err)
	}

	// 2. Save Public Key (PKIX PEM)
	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal public key: %w", err)
	}
	pubBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}
	pubFile, err := os.OpenFile(pubPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open public key file: %w", err)
	}
	defer pubFile.Close()
	if err := pem.Encode(pubFile, pubBlock); err != nil {
		return nil, nil, fmt.Errorf("failed to encode public key PEM: %w", err)
	}

	return priv, pub, nil
}

// LoadPrivateKeyPEM loads an Ed25519 private key from a PEM file.
func LoadPrivateKeyPEM(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("invalid PEM block type or empty file")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("loaded key is not an Ed25519 private key")
	}
	return edKey, nil
}

// LoadPublicKeyFromFile loads an Ed25519 public key from a file.
// It supports PEM (PKIX public key), raw base64 string, or raw hex string.
func LoadPublicKeyFromFile(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("public key file is empty")
	}

	// 1. Try PEM decode
	block, _ := pem.Decode(trimmed)
	if block != nil && block.Type == "PUBLIC KEY" {
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key from PKIX PEM: %w", err)
		}
		edKey, ok := key.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("loaded PEM key is not an Ed25519 public key")
		}
		return edKey, nil
	}

	// 2. Try hex decode (Ed25519 public keys are 32 bytes, which translates to 64 hex characters)
	strVal := string(trimmed)
	if len(strVal) == 64 {
		decoded, err := hex.DecodeString(strVal)
		if err == nil && len(decoded) == ed25519.PublicKeySize {
			return ed25519.PublicKey(decoded), nil
		}
	}

	// 3. Try base64 decode (both standard and URL encoding, with or without padding)
	strVal = strings.TrimSuffix(strVal, "\n")
	strVal = strings.TrimSuffix(strVal, "\r")
	
	// Helper to try different base64 alphabets
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
		decoded, err := enc.DecodeString(strVal)
		if err == nil && len(decoded) == ed25519.PublicKeySize {
			return ed25519.PublicKey(decoded), nil
		}
	}

	return nil, fmt.Errorf("could not decode public key (unrecognized format, expected PEM, 64-char Hex, or 44-char Base64)")
}

// SignChallenge creates a signature for a challenge string using the private key.
func SignChallenge(privKey ed25519.PrivateKey, agentID, timestamp string) string {
	challenge := fmt.Sprintf("%s:%s", agentID, timestamp)
	signatureBytes := ed25519.Sign(privKey, []byte(challenge))
	return base64.StdEncoding.EncodeToString(signatureBytes)
}

// VerifyChallenge verifies that the signature matches the challenge using the public key.
func VerifyChallenge(pubKey ed25519.PublicKey, agentID, timestamp, signature string) bool {
	challenge := fmt.Sprintf("%s:%s", agentID, timestamp)
	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false
	}
	return ed25519.Verify(pubKey, []byte(challenge), sigBytes)
}

// SavePublicKeyPEM encodes an Ed25519 public key in PKIX PEM format and saves it to a file.
func SavePublicKeyPEM(path string, pub ed25519.PublicKey) error {
	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}
	pubBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}
	pubFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open public key file: %w", err)
	}
	defer pubFile.Close()
	if err := pem.Encode(pubFile, pubBlock); err != nil {
		return fmt.Errorf("failed to encode public key PEM: %w", err)
	}
	return nil
}
