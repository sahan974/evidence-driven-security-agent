package case05

type FrameRequest struct {
	Payload []byte
}

type MessageEndpoint struct {
	parser FrameParser
}

func (endpoint MessageEndpoint) Type(request FrameRequest) byte {
	return endpoint.parser.Parse(request.Payload).messageType
}

func MessageType(input []byte) byte {
	return MessageEndpoint{parser: FrameParser{}}.Type(FrameRequest{Payload: input})
}
