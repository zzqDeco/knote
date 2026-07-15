package catalog

import "errors"

func ignoreUnsupportedDirectoryFlushError(err error, unsupported ...error) error {
	if err == nil {
		return nil
	}
	for _, candidate := range unsupported {
		if errors.Is(err, candidate) {
			return nil
		}
	}
	return err
}
