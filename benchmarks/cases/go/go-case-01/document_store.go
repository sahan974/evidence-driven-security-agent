package case01

import "os"

type DocumentStore struct{}

func (DocumentStore) ReadText(name string) ([]byte, error) {
	return os.ReadFile("documents/" + name)
}
