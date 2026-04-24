package core

import (
	"github.com/fixhq/memcall"
)

func init() {
	if err := memcall.DisableCoreDumps(); err != nil {
		panic("memguard: failed to disable core dumps: " + err.Error())
	}
}
