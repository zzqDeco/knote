//go:build windows

package kag

import (
	"os"
	"os/exec"
)

func configureAdapterCommand(_ *exec.Cmd) {}

func killAdapterCommand(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return os.ErrProcessDone
	}
	return cmd.Process.Kill()
}
