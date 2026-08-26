package case02

import "os/exec"

func InspectHost(host string) ([]byte, error) {
	return exec.Command("nslookup", host).Output()
}
