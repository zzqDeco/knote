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

const (
	// SafeToolAssistantReplayClassKey and V1 are persisted wire values shared
	// by the safe Eino producer and permissioned replay validator.
	SafeToolAssistantReplayClassKey = "replay_class"
	SafeToolAssistantReplayClassV1  = "safe-tool-assistant/v1"
)

type replayBlock struct {
	binding protocol.ProtectedContentBinding
	valid   bool
}

func (m *Manager) filterPersistedEvents(
	ctx context.Context,
	current protocol.AuthorizationContext,
	events []protocol.Event,
) []protocol.Event {
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
		if !block.valid || m.deps.AuthorizationContextProvider == nil || m.deps.ProtectedContentAuthorizer == nil {
			continue
		}
		if err := m.deps.ProtectedContentAuthorizer(ctx, current, block.binding); err == nil {
			allowed[blockID] = true
		}
	}

	filtered := make([]protocol.Event, 0, len(events))
	permissionedReplay := m.deps.AuthorizationContextProvider != nil
	slashTurn := false
	turnSessionID := ""
	classifiedSafeTool := false
	permissionedTurn := false
	for _, event := range events {
		if event.Type == protocol.EventUserMessage {
			slashTurn = strings.HasPrefix(strings.TrimSpace(event.Message), "/")
			turnSessionID = event.SessionID
			classifiedSafeTool = false
			permissionedTurn = false
		}
		if event.ProtectedContent != nil {
			slashTurn = false
			permissionedTurn = true
			if allowed[event.ProtectedContent.BlockID] {
				filtered = append(filtered, event)
			}
			continue
		}
		if permissionedReplayToolEvent(event) {
			permissionedTurn = true
		}
		if classifiedSafeToolReplayEvent(event, turnSessionID, current.SessionID) {
			classifiedSafeTool = true
		}
		unprotectedSlash := slashReplayEvent(event, slashTurn)
		safeToolAssistant := classifiedSafeToolAssistantReplayEvent(
			event,
			turnSessionID,
			current.SessionID,
			classifiedSafeTool,
			permissionedTurn,
			slashTurn,
		)
		if event.Type == protocol.EventAssistantDone || event.Type == protocol.EventError {
			classifiedSafeTool = false
			if unprotectedSlash {
				slashTurn = false
			}
		}
		if permissionedReplay && legacyProtectedEvent(event) && !unprotectedSlash && !safeToolAssistant {
			continue
		}
		filtered = append(filtered, event)
	}
	return filtered
}

func classifiedSafeToolReplayEvent(event protocol.Event, turnSessionID, currentSessionID string) bool {
	if event.Type != protocol.EventToolComplete ||
		turnSessionID == "" ||
		turnSessionID != currentSessionID ||
		event.SessionID != turnSessionID ||
		eventPayloadValue(event.Payload, SafeToolAssistantReplayClassKey) != SafeToolAssistantReplayClassV1 {
		return false
	}
	toolName := eventToolName(event.Payload)
	return toolName != "" && !permissionedToolName(toolName)
}

func classifiedSafeToolAssistantReplayEvent(
	event protocol.Event,
	turnSessionID string,
	currentSessionID string,
	classifiedSafeTool bool,
	permissionedTurn bool,
	slashTurn bool,
) bool {
	return event.Type == protocol.EventAssistantDone &&
		classifiedSafeTool &&
		!permissionedTurn &&
		!slashTurn &&
		turnSessionID != "" &&
		turnSessionID == currentSessionID &&
		event.SessionID == turnSessionID &&
		eventPayloadValue(event.Payload, SafeToolAssistantReplayClassKey) == SafeToolAssistantReplayClassV1
}

func permissionedReplayToolEvent(event protocol.Event) bool {
	switch event.Type {
	case protocol.EventToolStart, protocol.EventToolProgress, protocol.EventToolComplete, protocol.EventToolError:
		return permissionedToolName(eventToolName(event.Payload))
	default:
		return false
	}
}

func permissionedToolName(toolName string) bool {
	return toolName == einotools.NameQuery || toolName == einotools.NameExplain
}

func slashReplayEvent(event protocol.Event, slashTurn bool) bool {
	if eventPayloadValue(event.Payload, "source") == "slash" {
		return true
	}
	if !slashTurn {
		return false
	}
	switch event.Type {
	case protocol.EventAssistantDelta, protocol.EventAssistantDone, protocol.EventError:
		return true
	default:
		return false
	}
}

func legacyProtectedEvent(event protocol.Event) bool {
	switch event.Type {
	case protocol.EventAssistantDelta, protocol.EventAssistantDone, protocol.EventError:
		return true
	case protocol.EventToolStart, protocol.EventToolProgress, protocol.EventToolComplete, protocol.EventToolError:
		return permissionedToolName(eventToolName(event.Payload))
	default:
		return false
	}
}

func eventToolName(payload any) string {
	return eventPayloadValue(payload, "tool")
}

func eventPayloadValue(payload any, key string) string {
	switch value := payload.(type) {
	case map[string]string:
		return strings.TrimSpace(value[key])
	case map[string]any:
		item, _ := value[key].(string)
		return strings.TrimSpace(item)
	default:
		return ""
	}
}
