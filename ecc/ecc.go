package ecc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"math/big"
)

/**
	github.com/ethereum/go-ethereum v1.9.16

	@function signature:
	func GeneratePairs(model int) (*ecdsa.PrivateKey, *ecdsa.PublicKey)
	func Encrypt(text []byte, publicKey  *ecies.PublicKey) ([]byte, error)
	func Decrypt(text []byte, privateKey *ecies.PrivateKey) ([]byte, error)
	func Sign(text []byte, privateKey *ecdsa.PrivateKey) ([]byte, []byte)
	func Verify(text, rBytes, sBytes []byte, publicKey *ecdsa.PublicKey) bool
*/



func GenerateKey(model int) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	/*
		@params: model-曲线类型(默认224, 可选224、256、384、512)
		@return: 生成的ecc公私钥指针
	*/
	var curve elliptic.Curve

	switch model {
	case 224:
		curve = elliptic.P224()
	case 256:
		curve = elliptic.P256()
	case 384:
		curve = elliptic.P384()
	case 512:
		curve = elliptic.P521()
	default:
		curve = elliptic.P224()
	}

	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}
	publicKey := privateKey.PublicKey
	return privateKey, &publicKey
}


func GenerateKeyEth() (*ecies.PrivateKey, *ecies.PublicKey) {
	privateKey, err := ecies.GenerateKey(rand.Reader, elliptic.P256(), nil)
	if err != nil {
		panic(err)
	}
	publicKey := privateKey.PublicKey
	return privateKey, &publicKey
}




func SetPrivateKeyToPem(privateKey *ecdsa.PrivateKey) string {
	stream, err1 := x509.MarshalECPrivateKey(privateKey)
	if err1 != nil {
		return ""
	}
	block := &pem.Block{
		Type:    "ECC PRIVATE KEY",
		Bytes:   stream,
	}

	var buf bytes.Buffer
	err2 := pem.Encode(&buf, block)
	if err2 != nil {
		return ""
	}

	return buf.String()
}

func SetPublicKeyToPem(publicKey *ecdsa.PublicKey) string {
	stream, err1 := x509.MarshalPKIXPublicKey(publicKey)
	if err1 != nil {
		return ""
	}
	block := &pem.Block{
		Type:    "ECC PUBLIC KEY",
		Bytes:   stream,
	}

	var buf bytes.Buffer
	err2 := pem.Encode(&buf, block)
	if err2 != nil {
		return ""
	}

	return buf.String()
}


func GetPrivateKeyFromPem(privateKeyPem string) *ecdsa.PrivateKey {
	block, err1 := pem.Decode([]byte(privateKeyPem))
	if err1 != nil {
		return nil
	}

	privateKey, err2 := x509.ParseECPrivateKey(block.Bytes)
	if err2 != nil {
		return nil
	}

	return privateKey
}

func GetPublicKeyFromPem(publicKeyPem string) *ecdsa.PublicKey {
	block, err1 := pem.Decode([]byte(publicKeyPem))
	if err1 != nil {
		return nil
	}
	publicKey, err2 := x509.ParsePKIXPublicKey(block.Bytes)
	if err2 != nil {
		return nil
	}

	return publicKey.(*ecdsa.PublicKey)
}


func Encrypt(text []byte, publicKey  *ecies.PublicKey) []byte {
	/*
		@params: text-明文的byte形式；publicKey-以太坊封装的ecc公钥
		@return: 密文的byte形式；错误
	*/
	cipher, err := ecies.Encrypt(rand.Reader, publicKey, text, nil, nil)
	if err != nil {
		return nil
	}
	return cipher
}

func Decrypt(text []byte, privateKey *ecies.PrivateKey) []byte {
	/*
		@params: text-密文的byte形式；privateKey-以太坊封装的ecc私钥
		@return: 明文的byte形式；错误
	*/
	plaint, err := privateKey.Decrypt(text, nil, nil)
	if err != nil {
		return nil
	}
	return plaint
}



func Sign(text []byte, privateKey *ecdsa.PrivateKey) ([]byte, []byte) {
	/*
		@params: text-明文的byte形式；privateKey-标准库私钥
		@return: 签名r的byte形式；签名s的byte形式
	*/
	sha := sha256.New()
	sha.Write(text)
	hash := sha.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash)
	if err != nil {
		return nil, nil
	}
	rBytes, err := r.MarshalText()
	if err != nil {
		return nil, nil
	}
	sBytes, err := s.MarshalText()
	if err != nil {
		return nil, nil
	}

	return rBytes, sBytes
}

func Verify(text, rBytes, sBytes []byte, publicKey *ecdsa.PublicKey) bool {
	/*
		@params: text-明文的byte形式；签名r的byte形式；签名s的byte形式；publicKey-标准库公钥
		@return: true or false
	*/
	sha := sha256.New()
	sha.Write(text)
	hash := sha.Sum(nil)

	var r, s big.Int
	err := r.UnmarshalText(rBytes)
	if err != nil {
		return false
	}
	err = s.UnmarshalText(sBytes)
	if err != nil {
		return false
	}

	return ecdsa.Verify(publicKey, hash, &r, &s)
}
