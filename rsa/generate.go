package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
)


// GenerateKey generate new pairs by using key bits
func GenerateKey(bits int) (*rsa.PrivateKey, *rsa.PublicKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil
	}

	publicKey := privateKey.PublicKey

	return privateKey, &publicKey
}

// GenerateHexKey generate new rsa hex key pairs
func GenerateHexKey(bits int) (string, string) {
	privateKey, err1 := rsa.GenerateKey(rand.Reader, bits)
	if err1 != nil {
		return "", ""
	}
	rsaPrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)

	publicKey := privateKey.PublicKey
	rsaPublicKey, err2 := x509.MarshalPKIXPublicKey(&publicKey)
	if err2 != nil {
		return "", ""
	}

	return hex.EncodeToString(rsaPrivateKey), hex.EncodeToString(rsaPublicKey)
}

// GetPrivateKey gain rsa privateKey from hex key
func GetPrivateKey(hexKey string) *rsa.PrivateKey {
	key, err1 := hex.DecodeString(hexKey)
	if err1 != nil {
		return nil
	}
	privateKey, err2 := x509.ParsePKCS1PrivateKey(key)
	if err2 != nil {
		return nil
	}

	return privateKey
}

// GetPublicKey gain rsa publicKey from hex key
func GetPublicKey(hexKey string) *rsa.PublicKey {
	key, err1 := hex.DecodeString(hexKey)
	if err1 != nil {
		return nil
	}
	publicInterface, err2 := x509.ParsePKIXPublicKey(key)
	if err2 != nil {
		return nil
	}

	publicKey := publicInterface.(*rsa.PublicKey)

	return publicKey
}
