//go:build darwin || linux

package connector

import "os"

func replaceConnectorFile(source, target string) error { return os.Rename(source, target) }
