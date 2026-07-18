//go:build darwin || linux

package connector

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
)

func secureConnectorDirectory(path string) error { return os.Chmod(path, 0o700) }
func createConnectorDirectory(path string) error { return os.Mkdir(path, 0o700) }
func secureConnectorFile(file *os.File) error    { return file.Chmod(0o600) }

func validateConnectorPathComponent(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		if trustedImmutableConnectorPathAlias(path, info) {
			return nil
		}
		return fmt.Errorf("connector store path component is not a real directory: %s", path)
	}
	if !info.IsDir() {
		return fmt.Errorf("connector store path component is not a real directory: %s", path)
	}
	return nil
}

func validateConnectorDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("connector store directory is not a real directory: %s", path)
	}
	if info.Mode().Perm() != 0o700 {
		return fmt.Errorf("connector store directory permissions must be 0700: %s", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("connector store directory owner is unavailable: %s", path)
	}
	if !connectorDirectoryUIDOwnedByCurrentUser(stat.Uid) {
		return fmt.Errorf("connector store directory must be owned by the current user: %s", path)
	}
	return nil
}

func connectorDirectoryUIDOwnedByCurrentUser(uid uint32) bool {
	return uid == uint32(os.Geteuid())
}

func trustedImmutableConnectorPathAlias(path string, info os.FileInfo) bool {
	if runtime.GOOS != "darwin" || filepath.Clean(path) != "/var" {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return false
	}
	target, err := os.Readlink(path)
	if err != nil {
		return false
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(path), target)
	}
	target = filepath.Clean(target)
	return target == "/private/var" && immutableRootOwnedDirectoryChain(target)
}

func immutableRootOwnedDirectoryChain(path string) bool {
	relative := strings.TrimPrefix(filepath.Clean(path), string(filepath.Separator))
	current := string(filepath.Separator)
	components := []string{}
	if relative != "" {
		components = strings.Split(relative, string(filepath.Separator))
	}
	for index := -1; index < len(components); index++ {
		if index >= 0 {
			current = filepath.Join(current, components[index])
		}
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
			return false
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return false
		}
	}
	return true
}
