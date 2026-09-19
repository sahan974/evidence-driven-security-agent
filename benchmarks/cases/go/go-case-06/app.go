package case06

type PreviewRequest struct {
	Size int
}

type PreviewEndpoint struct {
	builder PreviewBuilder
}

func (endpoint PreviewEndpoint) Get(request PreviewRequest) []byte {
	return endpoint.builder.Build(request.Size)
}

func Expand(size int) []byte {
	return PreviewEndpoint{builder: PreviewBuilder{}}.Get(PreviewRequest{Size: size})
}
