//go:build !windows

package main

import (
	"os"
	"syscall"
)

func restartProcess(token string) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	args := append(append([]string{}, os.Args...), "-token", token)
	return syscall.Exec(executable, args, os.Environ())
}
