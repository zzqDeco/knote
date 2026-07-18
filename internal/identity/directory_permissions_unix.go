//go:build !windows

package identity

import "os"

func directoryPermissionsTooBroad(mode os.FileMode) bool {
	return mode.Perm()&0o077 != 0
}
