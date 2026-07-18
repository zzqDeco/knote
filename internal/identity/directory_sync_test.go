package identity

import (
	"errors"
	"testing"
)

func TestIgnoreUnsupportedDirectoryFlushErrorIsExact(t *testing.T) {
	unsupported := errors.New("unsupported")
	wrapped := errors.New("wrapped")
	if err := ignoreUnsupportedDirectoryFlushError(nil, unsupported); err != nil {
		t.Fatalf("nil flush error = %v", err)
	}
	if err := ignoreUnsupportedDirectoryFlushError(unsupported, unsupported); err != nil {
		t.Fatalf("documented unsupported flush error = %v", err)
	}
	if err := ignoreUnsupportedDirectoryFlushError(wrapped, unsupported); !errors.Is(err, wrapped) {
		t.Fatalf("unexpected flush error was hidden: %v", err)
	}
}
