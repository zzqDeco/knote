package telemetry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

type Sink interface {
	Emit(context.Context, Record) error
}

type NopSink struct{}

func (NopSink) Emit(context.Context, Record) error { return nil }

type JSONLSink struct {
	mu sync.Mutex
	w  io.Writer
}

func NewJSONLSink(w io.Writer) *JSONLSink { return &JSONLSink{w: w} }

func (s *JSONLSink) Emit(ctx context.Context, record Record) error {
	if ctx == nil {
		return fmt.Errorf("%w: nil context", ErrInvalidRecord)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := record.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.w == nil {
		return fmt.Errorf("%w: nil writer", ErrInvalidRecord)
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	n, err := s.w.Write(payload)
	if err != nil {
		return err
	}
	if n != len(payload) {
		return io.ErrShortWrite
	}
	return nil
}
