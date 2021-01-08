package crypto

import (
	"encoding/base64"
	"encoding/hex"
)



// EnBase64 ...
func EnBase64(src []byte) string {
	return base64.StdEncoding.EncodeToString(src)
}

// DeBase64 ...
func DeBase64(src string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(src)
}


// EnHex ...
func EnHex(src []byte) string {
	return hex.EncodeToString(src)
}

// DeHex ...
func DeHex(src string) ([]byte, error) {
	return hex.DecodeString(src)
}
