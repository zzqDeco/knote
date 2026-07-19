package authz

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
)

var ErrToolAuthorizationDenied = errors.New("tool authorization denied")

type ToolResultGate func(
	context.Context,
	protocol.AuthorizationContext,
	protocol.ProtectedContentBinding,
) error

type ToolInvocationDeniedHandler func(context.Context, protocol.ToolAuthorizationManifest)

type ToolAuthorizationGateOptions struct {
	Authorizer             Authorizer
	Registry               *protocol.ToolManifestRegistry
	FinalAuthorizationGate func(context.Context, protocol.AuthorizationContext) error
	ResultGate             ToolResultGate
	InvocationDenied       ToolInvocationDeniedHandler
	Now                    func() time.Time
	NewCorrelationID       func() (string, error)
}

type ToolAuthorizationGate struct {
	authorizer             Authorizer
	registry               *protocol.ToolManifestRegistry
	finalAuthorizationGate func(context.Context, protocol.AuthorizationContext) error
	resultGate             ToolResultGate
	invocationDenied       ToolInvocationDeniedHandler
	now                    func() time.Time
	newCorrelationID       func() (string, error)
}

func (g *ToolAuthorizationGate) ManifestDigest() string {
	if g == nil || g.registry == nil {
		return ""
	}
	return g.registry.Digest()
}

func NewToolAuthorizationGate(options ToolAuthorizationGateOptions) (*ToolAuthorizationGate, error) {
	if options.Authorizer == nil {
		return nil, fmt.Errorf("tool authorization requires an authorizer")
	}
	if options.Registry == nil {
		return nil, fmt.Errorf("tool authorization requires a manifest registry")
	}
	if options.ResultGate == nil {
		return nil, fmt.Errorf("tool authorization requires a protected result gate")
	}
	for _, manifest := range options.Registry.Manifests() {
		if err := validateToolManifestPolicy(manifest); err != nil {
			return nil, err
		}
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.NewCorrelationID == nil {
		options.NewCorrelationID = randomToolCorrelationID
	}
	return &ToolAuthorizationGate{
		authorizer:             options.Authorizer,
		registry:               options.Registry,
		finalAuthorizationGate: options.FinalAuthorizationGate,
		resultGate:             options.ResultGate,
		invocationDenied:       options.InvocationDenied,
		now:                    options.Now,
		newCorrelationID:       options.NewCorrelationID,
	}, nil
}

func validateToolManifestPolicy(manifest protocol.ToolAuthorizationManifest) error {
	if err := manifest.Validate(); err != nil {
		return err
	}
	if manifest.SideEffect {
		if manifest.Relation != RelationCanEdit {
			return fmt.Errorf("side-effecting tool %q requires relation %q", manifest.ToolName, RelationCanEdit)
		}
		if manifest.ReturnObligation != protocol.ToolReturnNone {
			return fmt.Errorf("side-effecting tool %q must use a content-free return obligation", manifest.ToolName)
		}
		return nil
	}
	if manifest.Relation != RelationCanView {
		return fmt.Errorf("read-only tool %q requires relation %q", manifest.ToolName, RelationCanView)
	}
	if manifest.ReturnObligation == protocol.ToolReturnNone {
		return fmt.Errorf("read-only protected tool %q requires a typed return obligation", manifest.ToolName)
	}
	return nil
}

func (g *ToolAuthorizationGate) AuthorizeInvocation(
	ctx context.Context,
	authorization protocol.AuthorizationContext,
	toolName string,
) (protocol.ToolInvocationAuthorization, error) {
	manifest, request, ok := g.registeredRequest(toolName)
	if !ok || ctx == nil || ctx.Err() != nil || authorization.Validate() != nil {
		return protocol.ToolInvocationAuthorization{}, ErrToolAuthorizationDenied
	}
	if g.validateCurrent(ctx, authorization) != nil {
		g.reportInvocationDenied(ctx, manifest)
		return protocol.ToolInvocationAuthorization{}, ErrToolAuthorizationDenied
	}
	consistency, err := toolConsistency(authorization.Consistency)
	if err != nil {
		return protocol.ToolInvocationAuthorization{}, ErrToolAuthorizationDenied
	}
	decision, err := g.authorizer.Check(ctx, CheckRequest{
		User:                 TypeUser + ":" + authorization.PrincipalID,
		Relation:             manifest.Relation,
		Object:               TypeKnowledgeBase + ":" + authorization.KnowledgeBaseID,
		AuthorizationModelID: authorization.AuthorizationModelID,
		Consistency:          consistency,
		AgentTaskScope:       toolAgentTaskScope(authorization),
	})
	if err != nil || decision.AuthorizationModelID != authorization.AuthorizationModelID {
		return protocol.ToolInvocationAuthorization{}, ErrToolAuthorizationDenied
	}
	if !decision.Allowed {
		g.reportInvocationDenied(ctx, manifest)
		return protocol.ToolInvocationAuthorization{}, ErrToolAuthorizationDenied
	}
	correlationID, err := g.newCorrelationID()
	if err != nil {
		return protocol.ToolInvocationAuthorization{}, ErrToolAuthorizationDenied
	}
	invocation := protocol.ToolInvocationAuthorization{
		Version: protocol.EnterpriseContractVersion, CorrelationID: correlationID,
		TenantID: authorization.TenantID, KnowledgeBaseID: authorization.KnowledgeBaseID,
		PrincipalID: authorization.PrincipalID, AgentID: authorization.AgentID, TaskID: authorization.TaskID,
		SessionID: authorization.SessionID, RequestID: authorization.RequestID,
		ToolName: manifest.ToolName, Action: manifest.Action, Relation: manifest.Relation,
		AuthorizationModelID: authorization.AuthorizationModelID,
		IdentityWatermark:    authorization.IdentityWatermark, ACLWatermark: authorization.ACLWatermark,
		DelegationWatermark:       authorization.DelegationWatermark,
		AgentTaskScopeFingerprint: authorization.AgentTaskScopeFingerprint,
		SideEffect:                manifest.SideEffect,
		ReturnObligation:          manifest.ReturnObligation,
		Outcome:                   protocol.DecisionAllow,
		Consistency:               authorization.Consistency,
		CheckedAt:                 g.now().UTC(),
	}
	if err := invocation.ValidateFor(authorization, request); err != nil {
		return protocol.ToolInvocationAuthorization{}, ErrToolAuthorizationDenied
	}
	return invocation, nil
}

func (g *ToolAuthorizationGate) reportInvocationDenied(
	ctx context.Context,
	manifest protocol.ToolAuthorizationManifest,
) {
	if g != nil && g.invocationDenied != nil {
		g.invocationDenied(ctx, manifest)
	}
}

func (g *ToolAuthorizationGate) AuthorizeEvidenceResult(
	ctx context.Context,
	authorization protocol.AuthorizationContext,
	invocation protocol.ToolInvocationAuthorization,
	evidence protocol.EvidencePackage,
) (protocol.ToolAuthorizationEnvelope, error) {
	binding, err := protocol.NewProtectedContentBinding(authorization, evidence)
	if err != nil {
		return protocol.ToolAuthorizationEnvelope{}, ErrToolAuthorizationDenied
	}
	return g.authorizeProtectedResult(ctx, authorization, invocation, protocol.ToolReturnEvidence, binding)
}

func (g *ToolAuthorizationGate) AuthorizeResourceResult(
	ctx context.Context,
	authorization protocol.AuthorizationContext,
	invocation protocol.ToolInvocationAuthorization,
	resources []protocol.ProtectedResourceBinding,
) (protocol.ToolAuthorizationEnvelope, error) {
	binding, err := protocol.NewProtectedContentBindingFromResourcesForAuthorization(authorization, resources)
	if err != nil {
		return protocol.ToolAuthorizationEnvelope{}, ErrToolAuthorizationDenied
	}
	return g.authorizeProtectedResult(ctx, authorization, invocation, protocol.ToolReturnResources, binding)
}

func (g *ToolAuthorizationGate) AuthorizeContentFreeResult(
	ctx context.Context,
	authorization protocol.AuthorizationContext,
	invocation protocol.ToolInvocationAuthorization,
) (protocol.ToolAuthorizationEnvelope, error) {
	manifest, request, ok := g.registeredRequest(invocation.ToolName)
	if !ok || manifest.ReturnObligation != protocol.ToolReturnNone ||
		g.validateCurrent(ctx, authorization) != nil || invocation.ValidateFor(authorization, request) != nil {
		return protocol.ToolAuthorizationEnvelope{}, ErrToolAuthorizationDenied
	}
	result := newToolResultAuthorization(authorization, invocation, nil, nil)
	return g.validatedEnvelope(authorization, invocation, result)
}

// ValidateProtectedResultEnvelope independently reauthorizes a protected tool
// result at the event publication boundary. The received envelope is treated as
// untrusted transport data; current invocation and per-resource checks are run
// again against the trusted manifest registry before protected content is used.
func (g *ToolAuthorizationGate) ValidateProtectedResultEnvelope(
	ctx context.Context,
	authorization protocol.AuthorizationContext,
	toolName string,
	envelope protocol.ToolAuthorizationEnvelope,
	binding protocol.ProtectedContentBinding,
) error {
	manifest, _, ok := g.registeredRequest(toolName)
	if !ok || manifest.ReturnObligation == protocol.ToolReturnNone ||
		envelope.Invocation.ToolName != toolName ||
		g.registry.ValidateEnvelope(authorization, envelope) != nil ||
		binding.ValidateFor(authorization) != nil {
		return ErrToolAuthorizationDenied
	}

	invocation, err := g.AuthorizeInvocation(ctx, authorization, toolName)
	if err != nil {
		return ErrToolAuthorizationDenied
	}
	current, err := g.authorizeProtectedResult(
		ctx, authorization, invocation, manifest.ReturnObligation, binding,
	)
	if err != nil || !sameToolResultResources(envelope.Result.Resources, current.Result.Resources) {
		return ErrToolAuthorizationDenied
	}
	return nil
}

func sameToolResultResources(left, right []protocol.ResourceHandle) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func (g *ToolAuthorizationGate) authorizeProtectedResult(
	ctx context.Context,
	authorization protocol.AuthorizationContext,
	invocation protocol.ToolInvocationAuthorization,
	obligation protocol.ToolReturnObligation,
	binding protocol.ProtectedContentBinding,
) (protocol.ToolAuthorizationEnvelope, error) {
	manifest, request, ok := g.registeredRequest(invocation.ToolName)
	if !ok || manifest.ReturnObligation != obligation ||
		g.validateCurrent(ctx, authorization) != nil || invocation.ValidateFor(authorization, request) != nil ||
		binding.ValidateFor(authorization) != nil {
		return protocol.ToolAuthorizationEnvelope{}, ErrToolAuthorizationDenied
	}
	if err := g.resultGate(ctx, authorization, binding); err != nil {
		return protocol.ToolAuthorizationEnvelope{}, ErrToolAuthorizationDenied
	}
	canonical := append([]protocol.ProtectedResourceBinding(nil), binding.Resources...)
	sort.Slice(canonical, func(i, j int) bool {
		return canonical[i].Resource.ResourceID < canonical[j].Resource.ResourceID
	})
	resources := make([]protocol.ResourceHandle, len(canonical))
	decisions := make([]protocol.AuthorizationDecision, len(canonical))
	checkedAt := g.now().UTC()
	for index, protected := range canonical {
		if index > 0 && protected.Resource.ResourceID == canonical[index-1].Resource.ResourceID {
			return protocol.ToolAuthorizationEnvelope{}, ErrToolAuthorizationDenied
		}
		resources[index] = protected.Resource
		decisions[index] = protocol.AuthorizationDecision{
			CorrelationID: resultDecisionCorrelationID(invocation.CorrelationID, protected.Resource.ResourceID),
			RequestID:     authorization.RequestID, SessionID: authorization.SessionID,
			PrincipalID: authorization.PrincipalID, AgentID: authorization.AgentID, TaskID: authorization.TaskID,
			DelegationWatermark:       authorization.DelegationWatermark,
			AgentTaskScopeFingerprint: authorization.AgentTaskScopeFingerprint,
			Relation:                  manifest.Relation,
			Resource:                  protected.Resource,
			AuthorizationResource:     protected.AuthorizationResource,
			Outcome:                   protocol.DecisionAllow,
			AuthorizationModelID:      authorization.AuthorizationModelID,
			IdentityWatermark:         authorization.IdentityWatermark,
			ACLWatermark:              authorization.ACLWatermark,
			Consistency:               authorization.Consistency,
			CheckedAt:                 checkedAt,
		}
	}
	result := newToolResultAuthorization(authorization, invocation, resources, decisions)
	return g.validatedEnvelope(authorization, invocation, result)
}

func (g *ToolAuthorizationGate) validatedEnvelope(
	authorization protocol.AuthorizationContext,
	invocation protocol.ToolInvocationAuthorization,
	result protocol.ToolResultAuthorization,
) (protocol.ToolAuthorizationEnvelope, error) {
	envelope := protocol.ToolAuthorizationEnvelope{
		Version: protocol.EnterpriseContractVersion, ManifestDigest: g.registry.Digest(),
		Invocation: invocation, Result: result,
	}
	if err := g.registry.ValidateEnvelope(authorization, envelope); err != nil {
		return protocol.ToolAuthorizationEnvelope{}, ErrToolAuthorizationDenied
	}
	return envelope, nil
}

func (g *ToolAuthorizationGate) registeredRequest(
	toolName string,
) (protocol.ToolAuthorizationManifest, protocol.ToolInvocationRequest, bool) {
	if g == nil || g.registry == nil {
		return protocol.ToolAuthorizationManifest{}, protocol.ToolInvocationRequest{}, false
	}
	manifest, ok := g.registry.Lookup(toolName)
	if !ok {
		return protocol.ToolAuthorizationManifest{}, protocol.ToolInvocationRequest{}, false
	}
	request, err := manifest.InvocationRequest()
	if err != nil {
		return protocol.ToolAuthorizationManifest{}, protocol.ToolInvocationRequest{}, false
	}
	return manifest, request, true
}

func (g *ToolAuthorizationGate) validateCurrent(
	ctx context.Context,
	authorization protocol.AuthorizationContext,
) error {
	if g == nil || ctx == nil {
		return ErrToolAuthorizationDenied
	}
	if err := ctx.Err(); err != nil {
		return ErrToolAuthorizationDenied
	}
	if err := authorization.Validate(); err != nil {
		return ErrToolAuthorizationDenied
	}
	if g.finalAuthorizationGate == nil {
		if authorization.AgentID != "" {
			return ErrToolAuthorizationDenied
		}
		return nil
	}
	if err := g.finalAuthorizationGate(ctx, authorization); err != nil {
		return ErrToolAuthorizationDenied
	}
	return nil
}

func newToolResultAuthorization(
	authorization protocol.AuthorizationContext,
	invocation protocol.ToolInvocationAuthorization,
	resources []protocol.ResourceHandle,
	decisions []protocol.AuthorizationDecision,
) protocol.ToolResultAuthorization {
	return protocol.ToolResultAuthorization{
		Version: protocol.EnterpriseContractVersion, CorrelationID: invocation.CorrelationID,
		TenantID: authorization.TenantID, KnowledgeBaseID: authorization.KnowledgeBaseID,
		PrincipalID: authorization.PrincipalID, AgentID: authorization.AgentID, TaskID: authorization.TaskID,
		SessionID: authorization.SessionID, RequestID: authorization.RequestID,
		ToolName: invocation.ToolName, Action: invocation.Action, Relation: invocation.Relation,
		SideEffect: invocation.SideEffect, ReturnObligation: invocation.ReturnObligation,
		AuthorizationModelID: authorization.AuthorizationModelID,
		IdentityWatermark:    authorization.IdentityWatermark, ACLWatermark: authorization.ACLWatermark,
		DelegationWatermark:       authorization.DelegationWatermark,
		AgentTaskScopeFingerprint: authorization.AgentTaskScopeFingerprint,
		Resources:                 append([]protocol.ResourceHandle(nil), resources...),
		Decisions:                 append([]protocol.AuthorizationDecision(nil), decisions...),
	}
}

func toolAgentTaskScope(authorization protocol.AuthorizationContext) *AgentTaskScope {
	if authorization.AgentID == "" {
		return nil
	}
	user := TypeUser + ":" + authorization.PrincipalID
	agent := TypeAgent + ":" + authorization.AgentID
	task := TypeTask + ":" + authorization.TaskID
	return &AgentTaskScope{
		User: user, Agent: agent, Task: task,
		AuthorizationModelID: authorization.AuthorizationModelID,
		ContextualTuples: []Tuple{
			{User: user, Relation: RelationDelegate, Object: agent},
			{User: agent, Relation: RelationAgent, Object: task},
			{User: user, Relation: RelationAssignee, Object: task},
		},
	}
}

func toolConsistency(value protocol.ConsistencyPreference) (Consistency, error) {
	switch value {
	case protocol.ConsistencyHigherConsistency:
		return ConsistencyHigherConsistency, nil
	case protocol.ConsistencyMinimizeLatency:
		return ConsistencyMinimizeLatency, nil
	default:
		return "", ErrToolAuthorizationDenied
	}
}

func randomToolCorrelationID() (string, error) {
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "tool-" + hex.EncodeToString(raw[:]), nil
}

func resultDecisionCorrelationID(invocationID string, resourceID protocol.ResourceID) string {
	sum := sha256.Sum256([]byte(invocationID + "\x00" + string(resourceID)))
	return "toolr-" + hex.EncodeToString(sum[:12])
}
