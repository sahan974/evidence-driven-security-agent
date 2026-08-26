package case01

import "os"

func LoadDocument(name string) ([]byte, error) {
	return os.ReadFile("documents/" + name)
}
