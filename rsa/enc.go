package rsa

import (
	"crypto/rand"
	"crypto/rsa"
)



// Encrypt rsa encrypt
func Encrypt(text []byte, publicKey *rsa.PublicKey) []byte {
	cipher, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, text)
	if err != nil {
		return nil
	}

	return cipher
}

// Decrypt rsa decrypt
func Decrypt(text []byte, privateKey *rsa.PrivateKey) []byte {
	plaint, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, text)
	if err != nil {
		return nil
	}

	return plaint
}
