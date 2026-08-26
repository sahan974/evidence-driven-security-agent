package case04

import "encoding/json"

func DecodeProfile(input []byte) (map[string]string, error) {
	profile := map[string]string{}
	err := json.Unmarshal(input, &profile)
	return profile, err
}
