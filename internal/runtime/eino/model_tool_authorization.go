package eino

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	einotool "github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"

	"github.com/zzqDeco/knote/internal/protocol"
)

const modelToolAuthorizationTokenField = "authorization_result_token"

var errModelToolAuthorization = errors.New("model tool authorization failed")

type modelToolAuthorizationContextKey struct{}

type modelToolAuthorizationRecord struct {
	toolName     string
	outputDigest [sha256.Size]byte
	envelope     protocol.ToolAuthorizationEnvelope
}

type modelToolAuthorizationState struct {
	mu        sync.Mutex
	secret    [sha256.Size]byte
	validator ToolAuthorizationValidator
	records   map[string]modelToolAuthorizationRecord
}

type modelAuthorizedTool struct {
	tool           einotool.InvokableTool
	toolName       string
	manifestDigest string
}

var _ einotool.InvokableTool = (*modelAuthorizedTool)(nil)

// PrepareModelTools ensures protected model tools never return a complete
// authorization envelope to the model provider. The envelope remains in a
// per-run state and is represented in model-visible JSON by a one-use token.
func PrepareModelTools(tools []einotool.InvokableTool) ([]einotool.InvokableTool, error) {
	prepared := make([]einotool.InvokableTool, 0, len(tools))
	for _, candidate := range tools {
		if candidate == nil {
			continue
		}
		info, err := candidate.Info(context.Background())
		if err != nil {
			return nil, fmt.Errorf("load model tool authorization metadata: %w", err)
		}
		if info == nil {
			return nil, errors.New("model tool authorization metadata is unavailable")
		}
		if !permissionedToolName(info.Name) {
			prepared = append(prepared, candidate)
			continue
		}
		marker, ok := candidate.(toolAuthorizationManifestDigester)
		if !ok || strings.TrimSpace(marker.ToolAuthorizationManifestDigest()) == "" {
			return nil, fmt.Errorf("permissioned model tool %q has no authorization manifest", info.Name)
		}
		prepared = append(prepared, &modelAuthorizedTool{
			tool:           candidate,
			toolName:       info.Name,
			manifestDigest: marker.ToolAuthorizationManifestDigest(),
		})
	}
	return prepared, nil
}

func (t *modelAuthorizedTool) Info(ctx context.Context) (*schema.ToolInfo, error) {
	return t.tool.Info(ctx)
}

func (t *modelAuthorizedTool) ToolAuthorizationManifestDigest() string {
	return t.manifestDigest
}

func (t *modelAuthorizedTool) InvokableRun(
	ctx context.Context,
	argumentsInJSON string,
	options ...einotool.Option,
) (string, error) {
	output, err := t.tool.InvokableRun(ctx, argumentsInJSON, options...)
	if err != nil {
		return "", err
	}
	sanitized, err := sanitizeModelToolAuthorizationOutput(
		ctx, t.toolName, t.manifestDigest, output,
	)
	if err != nil {
		return "", errModelToolAuthorization
	}
	return sanitized, nil
}

func withModelToolAuthorizationState(
	ctx context.Context,
	validator ToolAuthorizationValidator,
) (context.Context, *modelToolAuthorizationState, error) {
	if ctx == nil || validator == nil {
		return ctx, nil, errModelToolAuthorization
	}
	state := &modelToolAuthorizationState{
		validator: validator,
		records:   make(map[string]modelToolAuthorizationRecord),
	}
	if _, err := rand.Read(state.secret[:]); err != nil {
		return ctx, nil, errModelToolAuthorization
	}
	return context.WithValue(ctx, modelToolAuthorizationContextKey{}, state), state, nil
}

func modelToolAuthorizationStateFrom(ctx context.Context) (*modelToolAuthorizationState, bool) {
	if ctx == nil {
		return nil, false
	}
	state, ok := ctx.Value(modelToolAuthorizationContextKey{}).(*modelToolAuthorizationState)
	return state, ok && state != nil
}

func sanitizeModelToolAuthorizationOutput(
	ctx context.Context,
	toolName string,
	manifestDigest string,
	output string,
) (string, error) {
	state, ok := modelToolAuthorizationStateFrom(ctx)
	if !ok || state.validator == nil {
		return "", errModelToolAuthorization
	}
	authorization, ok := protocol.AuthorizationContextFrom(ctx)
	if !ok {
		return "", errModelToolAuthorization
	}
	envelope, err := decodeToolAuthorizationEnvelope(output)
	if err != nil {
		return "", errModelToolAuthorization
	}
	if manifestDigest != "" && envelope.ManifestDigest != manifestDigest {
		return "", errModelToolAuthorization
	}
	evidence, err := decodeEvidencePackage(output)
	if err != nil {
		return "", errModelToolAuthorization
	}
	binding, err := protocol.NewProtectedContentBinding(authorization, evidence)
	if err != nil {
		return "", errModelToolAuthorization
	}
	if err := state.validator.ValidateProtectedResultEnvelope(
		ctx, authorization, toolName, envelope, binding,
	); err != nil {
		return "", errModelToolAuthorization
	}

	sanitized, _, err := validateAndSanitizeToolAuthorizationOutput(
		output, toolName, envelope.ManifestDigest, authorization,
	)
	if err != nil {
		return "", errModelToolAuthorization
	}
	object, ok := sanitized.(map[string]any)
	if !ok {
		return "", errModelToolAuthorization
	}
	delete(object, "authorization_correlation_id")
	delete(object, "authorization_manifest_digest")
	if _, exists := object[modelToolAuthorizationTokenField]; exists {
		return "", errModelToolAuthorization
	}
	token, err := state.issue(toolName, envelope, object)
	if err != nil {
		return "", errModelToolAuthorization
	}
	object[modelToolAuthorizationTokenField] = token
	encoded, err := json.Marshal(object)
	if err != nil {
		return "", errModelToolAuthorization
	}
	return string(encoded), nil
}

func (s *modelToolAuthorizationState) issue(
	toolName string,
	envelope protocol.ToolAuthorizationEnvelope,
	output map[string]any,
) (string, error) {
	canonical, err := json.Marshal(output)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	mac := hmac.New(sha256.New, s.secret[:])
	_, _ = mac.Write([]byte(toolName))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(envelope.Invocation.CorrelationID))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(digest[:])
	token := "tool_result_" + hex.EncodeToString(mac.Sum(nil))

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.records[token]; exists {
		return "", errModelToolAuthorization
	}
	s.records[token] = modelToolAuthorizationRecord{
		toolName:     toolName,
		outputDigest: digest,
		envelope:     envelope,
	}
	return token, nil
}

func (s *modelToolAuthorizationState) consume(
	toolName string,
	output string,
) (protocol.ToolAuthorizationEnvelope, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &object); err != nil || object == nil {
		return protocol.ToolAuthorizationEnvelope{}, errModelToolAuthorization
	}
	rawToken, ok := object[modelToolAuthorizationTokenField]
	if !ok {
		return protocol.ToolAuthorizationEnvelope{}, errModelToolAuthorization
	}
	var token string
	if err := json.Unmarshal(rawToken, &token); err != nil || !strings.HasPrefix(token, "tool_result_") {
		return protocol.ToolAuthorizationEnvelope{}, errModelToolAuthorization
	}
	delete(object, modelToolAuthorizationTokenField)
	canonical, err := json.Marshal(object)
	if err != nil {
		return protocol.ToolAuthorizationEnvelope{}, errModelToolAuthorization
	}
	digest := sha256.Sum256(canonical)

	s.mu.Lock()
	record, exists := s.records[token]
	if exists {
		delete(s.records, token)
	}
	s.mu.Unlock()
	if !exists || record.toolName != toolName || !hmac.Equal(record.outputDigest[:], digest[:]) {
		return protocol.ToolAuthorizationEnvelope{}, errModelToolAuthorization
	}
	return record.envelope, nil
}
