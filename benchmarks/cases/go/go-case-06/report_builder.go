package case06

import "bytes"

type PreviewBuilder struct{}

func (PreviewBuilder) Build(size int) []byte {
	return bytes.Repeat([]byte("x"), size*size)
}
