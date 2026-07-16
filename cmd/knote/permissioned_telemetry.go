package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"time"

	"github.com/zzqDeco/knote/internal/telemetry"
)

const permissionedTelemetryEmitTimeout = 250 * time.Millisecond

var errPermissionedTelemetryTimeout = errors.New("permissioned telemetry emit timed out")

type permissionedTelemetryFileSink struct {
	path         string
	gate         chan struct{}
	appendRecord func(string, []byte) error
}

func newPermissionedTelemetrySink(path string) telemetry.Sink {
	if path == "" {
		return telemetry.NopSink{}
	}
	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	return &permissionedTelemetryFileSink{
		path:         path,
		gate:         gate,
		appendRecord: appendPermissionedTelemetryRecord,
	}
}

func (s *permissionedTelemetryFileSink) Emit(ctx context.Context, record telemetry.Record) error {
	if ctx == nil {
		return telemetry.ErrInvalidRecord
	}
	var encoded bytes.Buffer
	if err := telemetry.NewJSONLSink(&encoded).Emit(ctx, record); err != nil {
		return err
	}

	timer := time.NewTimer(permissionedTelemetryEmitTimeout)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return errPermissionedTelemetryTimeout
	case <-s.gate:
	}

	done := make(chan error, 1)
	payload := append([]byte(nil), encoded.Bytes()...)
	go func() {
		done <- s.appendRecord(s.path, payload)
		s.gate <- struct{}{}
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return errPermissionedTelemetryTimeout
	case err := <-done:
		return err
	}
}

func appendPermissionedTelemetryRecord(path string, encoded []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	written, writeErr := file.Write(encoded)
	if writeErr == nil && written != len(encoded) {
		writeErr = io.ErrShortWrite
	}
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}
