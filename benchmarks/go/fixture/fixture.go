package fixture

import "os"

func ParseMalformed(input []byte) byte {
	return input[8]
}

func ReadUserFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}
