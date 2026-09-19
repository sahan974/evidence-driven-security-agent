package case01

import (
	"fmt"
	"strings"
)

type DocumentService struct {
	store DocumentStore
}

func NewDocumentService() DocumentService {
	return DocumentService{store: DocumentStore{}}
}

func (service DocumentService) Retrieve(requestedName string) ([]byte, error) {
	name := strings.TrimSpace(requestedName)
	if name == "" {
		return nil, fmt.Errorf("a document name is required")
	}
	return service.store.ReadText(name)
}
