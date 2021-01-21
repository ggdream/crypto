package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)



// Sign rsa sign
func Sign(text []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	hash := sha256.New()
	if _, err := hash.Write(text); err != nil {
		return nil, err
	}

	return rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash.Sum(nil))
}

// Verify sign verify
func Verify(text, sign []byte, publicKey *rsa.PublicKey) bool {
	hash := sha256.New()
	if _, err := hash.Write(text); err != nil {
		return false
	}

	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash.Sum(nil), sign) == nil
}
