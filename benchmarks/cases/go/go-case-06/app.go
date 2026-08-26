package case06

import "bytes"

func Expand(size int) []byte {
	return bytes.Repeat([]byte("x"), size*size)
}
