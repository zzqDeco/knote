package connector

import (
	"context"
	"errors"
	"testing"

	"github.com/zzqDeco/knote/internal/protocol"
)

func TestProcessorTreatsTypedNilApplyErrorAsRetryableProjectorError(t *testing.T) {
	_, processor, ref := newTestProcessor(
		t, t.TempDir(), nil, RetryPolicy{MaxAttempts: 2}, newTestClock(),
	)
	event := testConnectorEvent(t, ref, 1, protocol.ConnectorContentUpsert, "doc-a", "content-a")
	var typedNil *ApplyError
	calls := 0
	projector := ProjectorFunc(func(context.Context, ApplyRequest) (ApplyResult, error) {
		calls++
		return ApplyResult{}, typedNil
	})

	result, err := processor.Process(context.Background(), ref, event, projector)
	if !errors.Is(err, ErrDeadLettered) {
		t.Fatalf("Process error = %v, want ErrDeadLettered", err)
	}
	if calls != 2 {
		t.Fatalf("projector calls = %d, want 2", calls)
	}
	if !result.DeadLetter || result.Receipt == nil {
		t.Fatalf("dead-letter result = %+v", result)
	}
	if result.Receipt.Attempts != 2 || result.Receipt.ErrorCode != "projector-error" {
		t.Fatalf("receipt = %+v, want 2 retry attempts with projector-error", result.Receipt)
	}
}
