//go:build windows

package identity

import "os"

// Windows access control is ACL-based; FileMode permission bits do not
// represent whether another principal can access the directory.
func directoryPermissionsTooBroad(os.FileMode) bool {
	return false
}
