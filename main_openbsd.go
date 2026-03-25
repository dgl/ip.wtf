package main

import (
	"golang.org/x/sys/unix"
)

func sandboxSelf() {
	unix.Unveil(*flagMaxMindDB, "r")
	unix.Unveil(*flagMaxMindDBASN, "r")
	unix.Unveil("/dev/null", "r")
	unix.Unveil("/etc/localtime", "r")
	unix.Unveil("/usr/share/zoneinfo", "r")
	unix.PledgePromises("stdio inet rpath")
}
