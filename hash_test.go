package crypto

import (
	"fmt"
	"testing")


func TestHash(t *testing.T) {
	data, err := Hash(DefineMD5, []byte("我喜欢你"))
	if err != nil {
		panic(err)
	}
	fmt.Println(data)
}

func TestPtr(t *testing.T) {
	data := "魔咔啦咔"
	slice := StringToSlice(data)
	fmt.Println(slice)
}
