package crypto

import "unsafe"



// SliceToString ...
func SliceToString(data []byte) string {
	return *(*string)(unsafe.Pointer(&data))
}

// StringToSlice ...
func StringToSlice(data string) []byte {
	return *(*[]byte)(unsafe.Pointer(&data))
}
