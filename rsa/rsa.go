package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"math/big"
)


func GenerateKey(bits int) (*rsa.PrivateKey, *rsa.PublicKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil
	}

	publicKey := privateKey.PublicKey

	return privateKey, &publicKey
}


// generate rsa hex key pairs
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


// 获取公钥的指数和模数
func GetEN(publicKey *rsa.PublicKey) (int, *big.Int) {
	return publicKey.E, publicKey.N
}


// gain rsa privateKey
func GetPrivateKey(hexKey string) *rsa.PrivateKey {
	key, _ := hex.DecodeString(hexKey)
	privateKey, _ := x509.ParsePKCS1PrivateKey(key)

	return privateKey
}


// gain rsa publicKey
func GetPublicKey(hexKey string) *rsa.PublicKey {
	key, _ := hex.DecodeString(hexKey)
	publicInterface, _ := x509.ParsePKIXPublicKey(key)
	publicKey := publicInterface.(*rsa.PublicKey)

	return publicKey
}


//// gain rsa privateKey from pem-format
//func GetPrivateKeyFromPem(privateKeyPem string) *rsa.PrivateKey {
//	block, _ := pem.Decode([]byte(privateKeyPem))
//	privateKey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
//
//	return privateKey
//}


// rsa encrypt
func Encrypt(text []byte, publicKey *rsa.PublicKey) []byte {
	cipher, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, text)
	if err != nil {
		return nil
	}

	return cipher
}


// rsa decrypt
func Decrypt(text []byte, privateKey *rsa.PrivateKey) []byte {
	plaint, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, text)
	if err != nil {
		return nil
	}

	return plaint
}


// rsa sign
func Sign(text []byte, privateKey *rsa.PrivateKey) []byte {
	hash := sha256.New()
	hash.Write(text)

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash.Sum(nil))
	if err != nil {
		return nil
	}

	return signature
}


// rsa sign verify
func Verify(text, sign []byte, publicKey *rsa.PublicKey) bool {
	hash := sha256.New()
	hash.Write(text)

	err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash.Sum(nil), sign)
	if err != nil {
		return false
	}

	return true
}
