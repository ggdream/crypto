# Golang的加解密、签验名的二次封装库

## 一、介绍

！！😫
。😘😘





## 二、安装

~~~shell
go get -u github.com/ggdream/crypto
~~~





## 三、例子

~~~go
package main

import (
	"fmt"
	"github.com/ggdream/crypto/rsa"
)


func main() {
	pri, pub := rsa.GenerateKey(1024)
    
	cipher := rsa.Encrypt([]byte("我喜欢你"), pub)
	fmt.Println(cipher)
    
	plaint := rsa.Decrypt(cipher, pri)
	fmt.Println(string(plaint))
}
~~~





## 四、函数签名

### 1. RSA

~~~go
// package: github.com/ggdream/crypto/rsa


// 操作秘钥
func GenerateKey(bits int) (*rsa.PrivateKey, *rsa.PublicKey)
func GenerateHexKey(bits int) (string, string)

func GetEN(publicKey *rsa.PublicKey) (string, string)
func SetEN(exp, mod string) *rsa.PublicKey

func GetPrivateKey(hexKey string) *rsa.PrivateKey
func GetPublicKey(hexKey string) *rsa.PublicKey

func SetPrivateKeyToPem(privateKey *rsa.PrivateKey) string
func SetPublicKeyToPem(publicKey *rsa.PublicKey) string
func GetPrivateKeyFromPem(privateKeyPem string) *rsa.PrivateKey
func GetPublicKeyFromPem(publicKeyPem string) *rsa.PublicKey


// 加密解密
func Encrypt(text []byte, publicKey *rsa.PublicKey) []byte
func Decrypt(text []byte, privateKey *rsa.PrivateKey) []byte

// 签名验签
func Sign(text []byte, privateKey *rsa.PrivateKey) []byte
func Verify(text, sign []byte, publicKey *rsa.PublicKey) bool
~~~



### 2. ECC

~~~go
// package: github.com/ggdream/crypto/ecc


// 操作秘钥
func GenerateKey(model int) (*ecdsa.PrivateKey, *ecdsa.PublicKey)
func GenerateKeyEth() (*ecies.PrivateKey, *ecies.PublicKey)

func SetPrivateKeyToPem(privateKey *ecdsa.PrivateKey) string
func SetPublicKeyToPem(publicKey *ecdsa.PublicKey) string
func GetPrivateKeyFromPem(privateKeyPem string) *ecdsa.PrivateKey
func GetPublicKeyFromPem(publicKeyPem string) *ecdsa.PublicKey


// 加密解密
func Encrypt(text []byte, publicKey  *ecies.PublicKey) []byte
func Decrypt(text []byte, privateKey *ecies.PrivateKey) []byte

// 签名验签
func Sign(text []byte, privateKey *ecdsa.PrivateKey) ([]byte, []byte)
func Verify(text, rBytes, sBytes []byte, publicKey *ecdsa.PublicKey) bool
~~~



### 3. AES

~~~go
// package: github.com/ggdream/crypto/aes


// 填充方式（AES并没有64位的块, 如果采用PKCS5, 那么实质上就是采用PKCS7。所以我封装的时候直接让PKCS7函数等上PKCS5函数）
func ZeroPadding(text []byte, blockSize int) []byte
func ZeroUnPadding(text []byte) []byte

func PKCS5Padding(text []byte, blockSize int) []byte
func PKCS5UnPadding(text []byte) []byte

var PKCS7Padding func(text []byte, blockSize int) []byte = PKCS5Padding
var PKCS7UnPadding func(text []byte) []byte = PKCS5UnPadding


// 加密解密（CBC模式。里面使用的填充方式是PKCS5(同时也可以被看做使用的是PKCS7)）
func Encrypt(text, key, iv []byte) []byte
func Decrypt(text, key, iv []byte) []byte
~~~





### 4. KEY

~~~go
// package: github.com/ggdream/crypto/key


// 依于MD5生成秘钥
func Gen16ByMD5() []byte

// 依于随机数生成秘钥
func GenByRand(bits int) []byte
func Gen16ByRand() []byte
func Gen32ByRand() []byte
func Gen64ByRand() []byte
~~~





### 5. HASH

~~~go
// file: github.com/ggdream/crypto/hashers.go

func MD5(text []byte) string
func SHA256(text []byte) []byte
func SHA512(text []byte) []byte
func FileMD5(file io.Reader) string
~~~



### 6. encode/decode

~~~go
// file: github.com/ggdream/crypto/coders.go


// Base64编解码
func EnBase64(src []byte) string
func DeBase64(src string) []byte

// 16进制编解码
func EnHex(src []byte) string
func DeHex(src string) []byte
~~~



### 7. byte[]/string

~~~go
// file: github.com/ggdream/crypto/ptr.go
// to change struct by using ptr.


// byte[]转string
func SliceToString(data []byte) string

// string转byte[]
func StringToSlice(data string) []byte
~~~

