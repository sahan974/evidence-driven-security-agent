package case04

type ProfileRequest struct {
	Payload []byte
}

type ProfileEndpoint struct {
	codec ProfileCodec
}

func (endpoint ProfileEndpoint) Decode(request ProfileRequest) (map[string]string, error) {
	return endpoint.codec.Decode(request.Payload)
}

func DecodeProfile(input []byte) (map[string]string, error) {
	return ProfileEndpoint{codec: ProfileCodec{}}.Decode(ProfileRequest{Payload: input})
}
