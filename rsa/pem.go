package rsa

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)


func SetPrivateKeyToPem(privateKey *rsa.PrivateKey) string {
	stream := x509.MarshalPKCS1PrivateKey(privateKey)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: stream,
	}

	var buf bytes.Buffer
	err := pem.Encode(&buf, block)
	if err != nil {
		return ""
	}

	return buf.String()
}

func SetPublicKeyToPem(publicKey *rsa.PublicKey) string {
	stream := x509.MarshalPKCS1PublicKey(publicKey)
	block := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: stream,
	}

	var buf bytes.Buffer
	err := pem.Encode(&buf, block)
	if err != nil {
		return ""
	}

	return buf.String()
}

func GetPrivateKeyFromPem(privateKeyPem string) *rsa.PrivateKey {
	block, _ := pem.Decode([]byte(privateKeyPem))

	privateKey, err2 := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err2 != nil {
		return nil
	}

	return privateKey
}

func GetPublicKeyFromPem(publicKeyPem string) *rsa.PublicKey {
	block, _ := pem.Decode([]byte(publicKeyPem))

	publicKey, err2 := x509.ParsePKCS1PublicKey(block.Bytes)
	if err2 != nil {
		return nil
	}

	return publicKey
}