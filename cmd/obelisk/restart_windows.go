package main

import (
	"os"
	"os/exec"
	"syscall"
)

func restartProcess(token string) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	args := append(append([]string{}, os.Args[1:]...), "-token", token)
	cmd := exec.Command(executable, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Start()
}
