package fixture

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/zzqDeco/knote/internal/authz"
	"github.com/zzqDeco/knote/internal/knowledge/authorized"
	"github.com/zzqDeco/knote/internal/knowledge/kag"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/telemetry"
)

const (
	Alice = "alice"
	Bob   = "bob"

	TenantID             = "tenant_fake"
	KnowledgeBaseID      = "kb_fake"
	AuthorizationModelID = "01GAHCE4YVKPQEKZQHT2R89MQV"
	ProjectionVersion    = "prj_ffffffffffffffffffffffffffffffff"

	introResourceID        protocol.ResourceID = "res_00000000000000000000000000000001"
	deniedCanaryResourceID protocol.ResourceID = "res_00000000000000000000000000000002"
	overviewResourceID     protocol.ResourceID = "res_00000000000000000000000000000003"

	introContent        = "knote is local-first."
	deniedCanaryContent = "DENIED CANARY BODY must never cross the authorization boundary"
	overviewContent     = "knote exposes a versioned knowledge workflow."

	fakeOrganization   = "organization:tenant_fake"
	fakePrivateReaders = "group:fixture-private-readers"
	fakeSharedReaders  = "group:fixture-shared-readers"
)

var requestSequence atomic.Uint64

type ApplicationOptions struct {
	Cache            *authorized.QueryCache
	RetrieverVersion string
	PromptVersion    string
	Telemetry        telemetry.Sink
}

// Application exposes the fake permissioned service and its revocation path as
// one wiring unit. Tuple mutation stands in for the future revocation transport.
type Application struct {
	Service     *authorized.Service
	coordinator *authorized.RevocationCoordinator
	authorizer  *authz.LocalAuthorizer
}

// New returns a deterministic service for the fake KAG retrieve projection.
// Graph expansion stays disabled so this fixture continues to exercise the
// non-traversal permissioned query path.
func New(backend kag.PrimitiveBackend) (*authorized.Service, error) {
	service, _, err := newService(backend, ApplicationOptions{})
	return service, err
}

func NewApplication(backend kag.PrimitiveBackend, options ApplicationOptions) (*Application, error) {
	if options.Cache == nil {
		return nil, fmt.Errorf("create fixture application: query cache is required")
	}
	service, authorizer, err := newService(backend, options)
	if err != nil {
		return nil, err
	}
	coordinator, err := authorized.NewRevocationCoordinator(service)
	if err != nil {
		return nil, fmt.Errorf("create fixture revocation coordinator: %w", err)
	}
	return &Application{Service: service, coordinator: coordinator, authorizer: authorizer}, nil
}

func (a *Application) AuthorizeProtectedContent(
	ctx context.Context,
	current protocol.AuthorizationContext,
	binding protocol.ProtectedContentBinding,
) error {
	if a == nil || a.coordinator == nil {
		return authorized.ErrProtectedContentUnavailable
	}
	_, err := a.coordinator.AuthorizeProtectedContent(ctx, current, binding)
	return err
}

func (a *Application) Apply(
	ctx context.Context,
	request authorized.RevocationRequest,
) (authorized.RevocationReport, error) {
	if a == nil || a.coordinator == nil {
		return authorized.RevocationReport{}, authorized.ErrRevocationUnavailable
	}
	return a.coordinator.Apply(ctx, request)
}

func (a *Application) RemoveTuple(tuple authz.Tuple) error {
	if a == nil || a.authorizer == nil {
		return fmt.Errorf("fixture application authorizer is unavailable")
	}
	return a.authorizer.RemoveTuple(tuple)
}

func (a *Application) Authorizer() authz.Authorizer {
	if a == nil {
		return nil
	}
	return a.authorizer
}

// EnsureBuildKnowledgeBaseEditor keeps the fake build fixture aligned with the
// workspace-derived materialization scope. Only the fixture editor may receive
// this deterministic test-only grant.
func (a *Application) EnsureBuildKnowledgeBaseEditor(authorization protocol.AuthorizationContext) error {
	if a == nil || a.authorizer == nil || authorization.PrincipalID != Alice {
		return fmt.Errorf("fixture build editor is unavailable")
	}
	if err := authorization.Validate(); err != nil {
		return err
	}
	organization := "organization:" + authorization.TenantID
	knowledgeBase := "knowledge_base:" + authorization.KnowledgeBaseID
	for _, tuple := range []authz.Tuple{
		{User: "user:" + authorization.PrincipalID, Relation: authz.RelationMember, Object: organization},
		{User: organization, Relation: authz.RelationOrganization, Object: knowledgeBase},
		{User: "user:" + authorization.PrincipalID, Relation: authz.RelationEditor, Object: knowledgeBase},
	} {
		if err := a.authorizer.AddTuple(tuple); err != nil {
			return err
		}
	}
	return nil
}

func newService(
	backend kag.PrimitiveBackend,
	options ApplicationOptions,
) (*authorized.Service, *authz.LocalAuthorizer, error) {
	authorizer, err := authz.NewLocalAuthorizer(AuthorizationModelID, fixtureTuples())
	if err != nil {
		return nil, nil, fmt.Errorf("create fixture authorizer: %w", err)
	}
	loader := exactEvidenceLoader{items: fixtureEvidence()}
	service, err := authorized.New(authorized.Options{
		KAG:              backend,
		Authorizer:       authorizer,
		Loader:           loader,
		Cache:            options.Cache,
		RetrieverVersion: options.RetrieverVersion,
		PromptVersion:    options.PromptVersion,
		RetrieveLimit:    3,
		EvidenceLimit:    3,
		ExpandLimit:      0,
		Telemetry:        options.Telemetry,
		Now: func() time.Time {
			return time.Date(2026, time.July, 13, 0, 0, 0, 0, time.UTC)
		},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("create fixture service: %w", err)
	}
	return service, authorizer, nil
}

// Authorization creates a request-scoped authorization context. Each call
// receives a distinct request ID, including concurrent calls.
func Authorization(principal, sessionID string) protocol.AuthorizationContext {
	requestID := fmt.Sprintf("request_fixture_%020d", requestSequence.Add(1))
	return protocol.AuthorizationContext{
		Version:              protocol.SecurityContractVersion,
		TenantID:             TenantID,
		KnowledgeBaseID:      KnowledgeBaseID,
		PrincipalID:          principal,
		SessionID:            sessionID,
		RequestID:            requestID,
		AuthorizationModelID: AuthorizationModelID,
		IdentityWatermark:    "identity_fake_v1",
		ACLWatermark:         "acl_fake_v1",
		Consistency:          protocol.ConsistencyHigherConsistency,
	}
}

func fixtureTuples() []authz.Tuple {
	intro := fixtureResource(introResourceID, introContent).AuthorizationID
	canary := fixtureResource(deniedCanaryResourceID, deniedCanaryContent).AuthorizationID
	overview := fixtureResource(overviewResourceID, overviewContent).AuthorizationID
	return []authz.Tuple{
		{User: "user:" + Alice, Relation: authz.RelationMember, Object: fakePrivateReaders},
		{User: "user:" + Alice, Relation: authz.RelationMember, Object: fakeSharedReaders},
		{User: "user:" + Bob, Relation: authz.RelationMember, Object: fakeSharedReaders},
		{User: fakePrivateReaders + "#" + authz.RelationMember, Relation: authz.RelationMember, Object: fakeOrganization},
		{User: fakeSharedReaders + "#" + authz.RelationMember, Relation: authz.RelationMember, Object: fakeOrganization},
		{User: fakeOrganization, Relation: authz.RelationOrganization, Object: "knowledge_base:" + KnowledgeBaseID},
		{User: "user:" + Alice, Relation: authz.RelationEditor, Object: "knowledge_base:" + KnowledgeBaseID},
		{User: "user:" + Bob, Relation: authz.RelationViewer, Object: "knowledge_base:" + KnowledgeBaseID},
		{User: fakeOrganization, Relation: authz.RelationOrganization, Object: intro},
		{User: fakePrivateReaders + "#" + authz.RelationMember, Relation: authz.RelationViewer, Object: intro},
		{User: fakeOrganization, Relation: authz.RelationOrganization, Object: canary},
		{User: fakeOrganization, Relation: authz.RelationOrganization, Object: overview},
		{User: fakeSharedReaders + "#" + authz.RelationMember, Relation: authz.RelationViewer, Object: overview},
	}
}

func fixtureEvidence() map[protocol.ResourceID]protocol.EvidenceItem {
	return map[protocol.ResourceID]protocol.EvidenceItem{
		introResourceID:        fixtureItem(introResourceID, introContent, "cite_intro"),
		deniedCanaryResourceID: fixtureItem(deniedCanaryResourceID, deniedCanaryContent, "cite_denied_canary"),
		overviewResourceID:     fixtureItem(overviewResourceID, overviewContent, "cite_overview"),
	}
}

func fixtureItem(id protocol.ResourceID, content, citation string) protocol.EvidenceItem {
	resource := fixtureResource(id, content)
	supportResource := resource
	if resource.Type == protocol.ResourceEntity {
		supportResource = fixtureResource(overviewResourceID, overviewContent)
	}
	return protocol.EvidenceItem{
		Resource:   resource,
		Content:    content,
		Derivation: protocol.DerivationAnySupport,
		Supports: []protocol.ProvenanceSupport{{
			SupportID: "support_" + string(id),
			Resource:  supportResource,
			Evidence:  []protocol.ResourceHandle{supportResource},
			Complete:  true,
		}},
		Citation: protocol.Citation{Handle: citation, Resource: resource},
	}
}

func fixtureResource(id protocol.ResourceID, content string) protocol.ResourceHandle {
	resourceType := protocol.ResourceDocument
	if id == introResourceID || id == deniedCanaryResourceID {
		resourceType = protocol.ResourceEntity
	}
	return protocol.ResourceHandle{
		ResourceID:              id,
		Type:                    resourceType,
		TenantID:                TenantID,
		KnowledgeBaseID:         KnowledgeBaseID,
		AuthorizationID:         string(resourceType) + ":" + string(id),
		AuthorizationResourceID: id,
		ContentDigest:           protocol.NewContentDigest(content),
		Versions: protocol.ResourceVersions{
			Source:     "source_fake_v1",
			Content:    "content_fake_v1",
			ACL:        "acl_fake_v1",
			Index:      "index_" + ProjectionVersion,
			Graph:      "graph_" + ProjectionVersion,
			Projection: ProjectionVersion,
		},
		ServingState: protocol.ServingActive,
	}
}

type exactEvidenceLoader struct {
	items map[protocol.ResourceID]protocol.EvidenceItem
}

func (l exactEvidenceLoader) Load(ctx context.Context, handles []protocol.ResourceHandle) ([]protocol.EvidenceItem, error) {
	if ctx == nil {
		return nil, fmt.Errorf("fixture evidence load requires a context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	items := make([]protocol.EvidenceItem, len(handles))
	for index, handle := range handles {
		item, ok := l.items[handle.ResourceID]
		if !ok {
			return nil, fmt.Errorf("resource %s is not in the fake retrieve fixture", handle.ResourceID)
		}
		if item.Resource != handle {
			return nil, fmt.Errorf("resource %s does not match the exact fake retrieve handle", handle.ResourceID)
		}
		items[index] = cloneEvidenceItem(item)
	}
	return items, nil
}

func cloneEvidenceItem(item protocol.EvidenceItem) protocol.EvidenceItem {
	clone := item
	clone.Supports = make([]protocol.ProvenanceSupport, len(item.Supports))
	for index, support := range item.Supports {
		clone.Supports[index] = support
		clone.Supports[index].Evidence = append([]protocol.ResourceHandle(nil), support.Evidence...)
	}
	return clone
}
