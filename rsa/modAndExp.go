package rsa

import (
	"crypto/rsa"
	"math/big"
	"strconv"
)



// GetEN get mod and exp about the public key
func GetEN(publicKey *rsa.PublicKey) (string, string) {
	return strconv.FormatInt(int64(publicKey.E), 16), publicKey.N.Text(16)
}

// SetEN generate the public key by using mod and exp
func SetEN(exp, mod string) *rsa.PublicKey {
	e, err1 := strconv.ParseInt(exp, 16, 0)
	if err1 != nil {
		return nil
	}

	bigN := new(big.Int)
	bigN, err2 := bigN.SetString(mod, 16)
	if !err2 {
		return nil
	}

	return &rsa.PublicKey{
		N: bigN,
		E: int(e),
	}
}
