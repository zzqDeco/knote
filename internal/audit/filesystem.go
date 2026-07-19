package audit

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func canonicalAuditRoot(root string) (string, error) {
	if root == "" || root != strings.TrimSpace(root) {
		return "", fmt.Errorf("%w: audit store root is invalid", ErrInvalidInput)
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("%w: audit store root is invalid", ErrInvalidInput)
	}
	absolute = filepath.Clean(absolute)
	if absolute == filepath.VolumeName(absolute)+string(filepath.Separator) {
		return "", fmt.Errorf("%w: audit store root cannot be a filesystem root", ErrInvalidInput)
	}

	current := absolute
	missing := make([]string, 0, 2)
	for {
		info, err := os.Lstat(current)
		if err == nil {
			if len(missing) == 0 && info.Mode()&os.ModeSymlink != 0 {
				return "", fmt.Errorf("%w: audit store root cannot be a symlink", ErrInvalidInput)
			}
			if info.Mode()&os.ModeSymlink == 0 && !info.IsDir() {
				return "", fmt.Errorf("%w: audit store root parent is not a directory", ErrInvalidInput)
			}
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("inspect audit store root: %w", err)
		}
		missing = append(missing, filepath.Base(current))
		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("%w: audit store root has no existing parent", ErrInvalidInput)
		}
		current = parent
	}
	resolved, err := filepath.EvalSymlinks(current)
	if err != nil {
		return "", fmt.Errorf("resolve audit store root parent: %w", err)
	}
	for index := len(missing) - 1; index >= 0; index-- {
		resolved = filepath.Join(resolved, missing[index])
	}
	return filepath.Clean(resolved), nil
}

func ensureAuditDirectoryDurably(path string, syncDirectory func(string) error) error {
	path = filepath.Clean(path)
	missing := make([]string, 0, 3)
	current := path
	for {
		info, err := os.Lstat(current)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				return fmt.Errorf("audit directory is not a real directory: %s", current)
			}
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		missing = append(missing, current)
		parent := filepath.Dir(current)
		if parent == current {
			return fmt.Errorf("audit directory has no existing parent: %s", path)
		}
		current = parent
	}
	for index := len(missing) - 1; index >= 0; index-- {
		directory := missing[index]
		if err := os.Mkdir(directory, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		info, err := os.Lstat(directory)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("audit directory is not a real directory: %s", directory)
		}
		if err := os.Chmod(directory, 0o700); err != nil {
			return err
		}
		if err := syncDirectory(filepath.Dir(directory)); err != nil {
			return fmt.Errorf("sync parent of audit directory: %w", err)
		}
	}
	if len(missing) == 0 {
		if err := os.Chmod(path, 0o700); err != nil {
			return err
		}
	}
	return nil
}

func writeAuditFileAtomically(
	path string,
	data []byte,
	replace bool,
	syncDirectory func(string) error,
) error {
	directory := filepath.Dir(path)
	if info, err := os.Lstat(path); err == nil {
		if !replace {
			return os.ErrExist
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return integrityError("atomic audit target is not a regular file", nil)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".audit-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	written, err := temporary.Write(data)
	if err != nil {
		temporary.Close()
		return err
	}
	if written != len(data) {
		temporary.Close()
		return fmt.Errorf("write audit file: %w", io.ErrShortWrite)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if replace {
		err = replaceAuditFile(temporaryPath, path)
	} else {
		err = installAuditFile(temporaryPath, path)
	}
	if err != nil {
		return err
	}
	if err := syncDirectory(directory); err != nil {
		return fmt.Errorf("sync audit file directory: %w", err)
	}
	return nil
}

func truncateAuditFile(path string, size int64) error {
	if size <= 0 {
		return fmt.Errorf("invalid audit truncation size")
	}
	file, err := openAuditReadWrite(path)
	if err != nil {
		return err
	}
	closeFile := true
	defer func() {
		if closeFile {
			_ = file.Close()
		}
	}()
	if err := file.Truncate(size); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	closeFile = false
	return nil
}
