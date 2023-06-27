package main

import (
	"os"

	"golang.org/x/sys/unix"
)

func sandboxSelf() {
	cwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	unix.Unveil(cwd, "r")
	unix.UnveilBlock()
	unix.Pledge("stdio inet rpath", "")
}
