package key

import (
	"crypto/md5"
	"encoding/binary"
	"math/rand"
	"time"
)

func init(){
	rand.Seed(time.Now().UnixNano())
}

func Gen16ByMD5() []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(rand.Int63()))

	hash := md5.New()
	hash.Write(buf)
	return hash.Sum(nil)
}

func GenByRand(bits int) []byte {
	var buf []byte
	for i:=0;i<bits;i++ {
		buf = append(buf, uint8(rand.Intn(1 << 8)))
	}
	return buf
}

func Gen16ByRand() []byte {
	return GenByRand(16)
}

func Gen32ByRand() []byte {
	return GenByRand(32)
}

func Gen64ByRand() []byte {
	return GenByRand(64)
}
