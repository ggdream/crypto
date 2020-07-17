package crypto

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
)



func MD5(text []byte) string {
	return fmt.Sprintf("%x", md5.Sum(text))
}

func SHA256(text []byte) []byte {
	hash := sha256.New()
	hash.Write(text)
	return hash.Sum(nil)
}

func SHA512(text []byte) []byte {
	hash := sha512.New()
	hash.Write(text)
	return hash.Sum(nil)
}

func FileMD5(file io.Reader) string {
	hash := md5.New()
	_, err := io.Copy(hash, file)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(hash.Sum(nil))
}
