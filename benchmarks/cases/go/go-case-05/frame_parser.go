package case05

type frameHeader struct {
	messageType byte
}

type FrameParser struct{}

func (FrameParser) Parse(input []byte) frameHeader {
	return frameHeader{messageType: input[4]}
}
