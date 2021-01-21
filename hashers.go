package crypto

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"io"
	"strings"

	"golang.org/x/crypto/sha3"
)



// Predefine hash algorithm tag
const (
	DefineMD5			= "md5"
	DefineSHA1			= "sha1"
	DefineSHA224		= "sha224"
	DefineSHA256		= "sha256"
	DefineSHA384		= "sha384"
	DefineSHA512		= "sha512"
	DefineSHA3224		= "sha3-224"
	DefineSHA3256		= "sha3-256"
	DefineSHA3384		= "sha3-384"
	DefineSHA3512		= "sha3-512"
)

type Hasher struct {
	Data		[]byte
	Algorithm	string
}


// Hash define algorithm is md5
func Hash(algorithm string, data []byte) (string, error) {
	h := &Hasher{
		Data: data,
		Algorithm: algorithm,
	}
	return h.ToHex()
}

// GetHasher Get the hasher that you want
func (h *Hasher) GetHasher() hash.Hash {
	var hasher	hash.Hash

	switch strings.ToLower(h.Algorithm) {
	case DefineMD5:
		hasher = md5.New()
	case DefineSHA1:
		hasher = sha1.New()
	case DefineSHA224:
		hasher = sha256.New224()
	case DefineSHA256:
		hasher = sha256.New()
	case DefineSHA384:
		hasher = sha512.New384()
	case DefineSHA3224:
		hasher = sha3.New224()
	case DefineSHA3256:
		hasher = sha3.New256()
	case DefineSHA3384:
		hasher = sha3.New384()
	case DefineSHA3512:
		hasher = sha3.New512()
	default:
		hasher =  md5.New()
	}

	return hasher
}

// ToBytes Get origin hash data
func (h *Hasher) ToBytes() ([]byte, error) {
	hasher := h.GetHasher()

	_, err := hasher.Write(h.Data)
	if err != nil {
		return nil, err
	}

	return hasher.Sum(nil), nil
}

// ToBase64 Get final hash data by Base64
func (h *Hasher) ToBase64() (string, error) {
	data, err := h.ToBytes()
	if err != nil {
		return "", err
	}

	return EnBase64(data), nil
}

// ToHex Get final hash data by hex
func (h *Hasher) ToHex() (string, error) {
	data, err := h.ToBytes()
	if err != nil {
		return "", err
	}

	return EnHex(data), nil
}


// FileMD5 Hash the file stream
func FileMD5(file io.Reader) string {
	hash := md5.New()
	_, err := io.Copy(hash, file)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(hash.Sum(nil))
}
