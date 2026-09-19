package case01

type DocumentRequest struct {
	Name string
}

type DocumentEndpoint struct {
	service DocumentService
}

func NewDocumentEndpoint(service DocumentService) DocumentEndpoint {
	return DocumentEndpoint{service: service}
}

func (endpoint DocumentEndpoint) Get(request DocumentRequest) ([]byte, error) {
	return endpoint.service.Retrieve(request.Name)
}

func LoadDocument(name string) ([]byte, error) {
	return NewDocumentEndpoint(NewDocumentService()).Get(DocumentRequest{Name: name})
}
