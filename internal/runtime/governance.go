package runtime

import (
	"context"

	"github.com/zzqDeco/knote/internal/governance"
	"github.com/zzqDeco/knote/internal/protocol"
)

const governanceUnavailableMessage = "governance is unavailable in this session"

func (m *Manager) governanceView(ctx context.Context, sessionID string) []protocol.Event {
	if m.deps.Governance == nil {
		return []protocol.Event{protocol.NewEvent(protocol.EventError, sessionID, governanceUnavailableMessage, nil)}
	}
	authorization, ok := protocol.AuthorizationContextFrom(ctx)
	if !ok || authorization.SessionID != sessionID {
		return []protocol.Event{protocol.NewEvent(protocol.EventError, sessionID, governanceUnavailableMessage, nil)}
	}
	snapshot, err := m.deps.Governance.View(ctx, authorization)
	if err != nil {
		return []protocol.Event{protocol.NewEvent(protocol.EventError, sessionID, governanceUnavailableMessage, nil)}
	}
	return []protocol.Event{protocol.NewEvent(
		protocol.EventAssistantDone,
		sessionID,
		governance.Render(snapshot),
		map[string]any{"overlay": "governance", "snapshot": snapshot},
	)}
}
