//go:build darwin || linux

package local

import "os"

func replaceArtifactFile(source, destination string) error {
	return os.Rename(source, destination)
}
