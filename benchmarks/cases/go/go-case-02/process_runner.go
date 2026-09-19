package case02

import "os/exec"

type ProcessRunner struct{}

func (ProcessRunner) Lookup(host string) ([]byte, error) {
	return exec.Command("nslookup", host).Output()
}
