package rsa

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strconv"
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
func GetEN(publicKey *rsa.PublicKey) (string, string) {
	return strconv.FormatInt(int64(publicKey.E), 16), publicKey.N.Text(16)
}


func SetEN(exp, mod string) *rsa.PublicKey {
	e, err1 := strconv.ParseInt(exp, 16, 0)
	if err1 != nil {
		return nil
	}

	bigN := new(big.Int)
	bigN, err2 := bigN.SetString(mod, 16)
	if err2 != true {
		return nil
	}
	
	return &rsa.PublicKey{
		N: bigN,
		E: int(e),
	}
}


// gain rsa privateKey
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


// gain rsa publicKey
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


func SetPrivateKeyToPem(privateKey *rsa.PrivateKey) string {
	stream := x509.MarshalPKCS1PrivateKey(privateKey)
	block := &pem.Block{
		Type:    "RSA PRIVATE KEY",
		Bytes:   stream,
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
		Type:    "RSA PUBLIC KEY",
		Bytes:   stream,
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
