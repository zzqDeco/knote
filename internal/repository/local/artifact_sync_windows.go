//go:build windows

package local

// Go does not expose a portable directory flush on Windows. Bundle files and
// the pointer temp file are individually flushed before their atomic renames.
func syncArtifactDirectory(string) error { return nil }
