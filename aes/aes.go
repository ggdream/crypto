package aes

import (
	"crypto/aes"
	"crypto/cipher"
)



// AES encrypt
func Encrypt(text, key, iv []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	text = PKCS5Padding(text, block.BlockSize())
	blockModel := cipher.NewCBCEncrypter(block, iv)
	ciphers := make([]byte, len(text))
	blockModel.CryptBlocks(ciphers, text)
	return ciphers
}

// AES decrypt
func Decrypt(text, key, iv []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	blockModel := cipher.NewCBCDecrypter(block, iv)
	plants := make([]byte, len(text))
	blockModel.CryptBlocks(plants, text)
	return PKCS5UnPadding(plants)
}