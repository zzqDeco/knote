package runtime

import (
	"context"
	"reflect"
	"sort"
	"strings"

	einotools "github.com/zzqDeco/knote/internal/eino/tools"
	"github.com/zzqDeco/knote/internal/protocol"
)

// ProtectedContentAuthorizer performs the live, higher-consistency check for
// one persisted protected-content block. Implementations must return an error
// for a deny or an unavailable authorization decision.
type ProtectedContentAuthorizer func(
	ctx context.Context,
	current protocol.AuthorizationContext,
	binding protocol.ProtectedContentBinding,
) error

type replayBlock struct {
	binding protocol.ProtectedContentBinding
	valid   bool
}

func (m *Manager) filterPersistedEvents(
	ctx context.Context,
	current protocol.AuthorizationContext,
	events []protocol.Event,
) []protocol.Event {
	if m.deps.AuthorizationContextProvider == nil {
		return append([]protocol.Event(nil), events...)
	}

	blocks := make(map[string]replayBlock)
	for _, event := range events {
		if event.ProtectedContent == nil {
			continue
		}
		binding := *event.ProtectedContent
		block := blocks[binding.BlockID]
		if block.binding.Version == "" {
			block.binding = binding
			block.valid = event.SessionID == current.SessionID && binding.ValidateFor(current) == nil
		} else if !reflect.DeepEqual(block.binding, binding) {
			block.valid = false
		}
		blocks[binding.BlockID] = block
	}

	allowed := make(map[string]bool, len(blocks))
	blockIDs := make([]string, 0, len(blocks))
	for blockID := range blocks {
		blockIDs = append(blockIDs, blockID)
	}
	sort.Strings(blockIDs)
	for _, blockID := range blockIDs {
		block := blocks[blockID]
		if !block.valid || m.deps.ProtectedContentAuthorizer == nil {
			continue
		}
		if err := m.deps.ProtectedContentAuthorizer(ctx, current, block.binding); err == nil {
			allowed[blockID] = true
		}
	}

	filtered := make([]protocol.Event, 0, len(events))
	for _, event := range events {
		if event.ProtectedContent != nil {
			if allowed[event.ProtectedContent.BlockID] {
				filtered = append(filtered, event)
			}
			continue
		}
		if legacyProtectedEvent(event) {
			continue
		}
		filtered = append(filtered, event)
	}
	return filtered
}

func legacyProtectedEvent(event protocol.Event) bool {
	switch event.Type {
	case protocol.EventAssistantDelta, protocol.EventAssistantDone, protocol.EventError:
		return true
	case protocol.EventToolStart, protocol.EventToolProgress, protocol.EventToolComplete, protocol.EventToolError:
		toolName := eventToolName(event.Payload)
		return toolName == einotools.NameQuery || toolName == einotools.NameExplain
	default:
		return false
	}
}

func eventToolName(payload any) string {
	switch value := payload.(type) {
	case map[string]string:
		return strings.TrimSpace(value["tool"])
	case map[string]any:
		name, _ := value["tool"].(string)
		return strings.TrimSpace(name)
	default:
		return ""
	}
}
