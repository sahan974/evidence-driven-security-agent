package fixture

import (
	"bytes"
	"fmt"
	"os"
	"testing"
)

func TestMalformedInputPanic(t *testing.T) {
	control := os.Getenv("EDSA_NEGATIVE_CONTROL") == "1"
	input := []byte("safe-data")
	if !control {
		input = []byte{0}
	}
	defer func() {
		if recovered := recover(); recovered != nil && !control {
			fmt.Println("EDSA_VULNERABLE")
		} else if recovered == nil && control {
			fmt.Println("EDSA_CONTROL_CLEAN")
		}
	}()
	_ = ParseMalformed(input)
}

func TestFilesystemBoundary(t *testing.T) {
	control := os.Getenv("EDSA_NEGATIVE_CONTROL") == "1"
	path := "../../../../../../etc/passwd"
	if control {
		path = "safe.txt"
	}
	content, err := ReadUserFile(path)
	if err != nil {
		fmt.Println("EDSA_NOT_REPRODUCED")
		return
	}
	vulnerable := bytes.Contains(content, []byte("root:"))
	if control && !vulnerable {
		fmt.Println("EDSA_CONTROL_CLEAN")
	} else if vulnerable {
		fmt.Println("EDSA_VULNERABLE")
	}
}

func FuzzMalformed(f *testing.F) {
	f.Add([]byte("safe-data"))
	f.Fuzz(func(t *testing.T, input []byte) {
		_ = ParseMalformed(input)
	})
}
