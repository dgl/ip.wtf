package main

import (
	"golang.org/x/sys/unix"
)

func sandboxSelf() {
	unix.UnveilBlock()
	unix.Pledge("stdio inet", "")
}
