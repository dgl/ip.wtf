package main

import (
	"golang.org/x/sys/unix"
)

func sandboxSelf() {
	unix.Unveil(*flagMaxMindDB, "r")
	unix.Unveil(*flagMaxMindDBASN, "r")
	unix.UnveilBlock()
	unix.Pledge("stdio inet", "")
}
