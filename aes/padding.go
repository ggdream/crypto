package aes

import "bytes"

/*
	AES并没有64位的块, 如果采用PKCS5, 那么实质上就是采用PKCS7
*/


func ZeroPadding(text []byte, blockSize int) []byte {
	padNum := blockSize - len(text) % blockSize
	padText := bytes.Repeat([]byte{0}, padNum)
	return append(text, padText...)
}
func ZeroUnPadding(text []byte) []byte {
	return bytes.TrimFunc(text,
		func(r rune) bool {
			return r == rune(0)
		})
}


func PKCS5Padding(text []byte, blockSize int) []byte {
	padNum := blockSize - len(text) % blockSize
	padText := bytes.Repeat([]byte{byte(padNum)}, padNum)
	return append(text, padText...)
}
func PKCS5UnPadding(text []byte) []byte {
	unNum := int(text[len(text) - 1])
	return text[:(len(text) - unNum)]
}


var PKCS7Padding func(text []byte, blockSize int) []byte = PKCS5Padding
var PKCS7UnPadding func(text []byte) []byte = PKCS5UnPadding
