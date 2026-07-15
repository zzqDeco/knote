//go:build darwin || linux

package catalog

import "os"

func replaceProjectionFile(source, target string) error {
	return os.Rename(source, target)
}
