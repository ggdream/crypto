package crypto

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
)



// MD5 ...
func MD5(text []byte) string {
	return fmt.Sprintf("%x", md5.Sum(text))
}

// SHA256 ...
func SHA256(text []byte) []byte {
	hash := sha256.New()
	hash.Write(text)
	return hash.Sum(nil)
}

// SHA512 ...
func SHA512(text []byte) []byte {
	hash := sha512.New()
	hash.Write(text)
	return hash.Sum(nil)
}

// FileMD5 ...
func FileMD5(file io.Reader) string {
	hash := md5.New()
	_, err := io.Copy(hash, file)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(hash.Sum(nil))
}
