package crypto

import (
	"encoding/base64"
	"encoding/hex"
)



func EnBase64(src []byte) string {
	return base64.StdEncoding.EncodeToString(src)
}
func DeBase64(src string) []byte {
	dst, err := base64.StdEncoding.DecodeString(src)
	if err != nil {
		return nil
	}
	return dst
}


func EnHex(src []byte) string {
	return hex.EncodeToString(src)
}
func DeHex(src string) []byte {
	dst, err := hex.DecodeString(src)
	if err != nil {
		return nil
	}
	return dst
}
