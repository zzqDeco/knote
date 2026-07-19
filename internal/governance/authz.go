package governance

import (
	"context"
	"fmt"

	"github.com/zzqDeco/knote/internal/authz"
	"github.com/zzqDeco/knote/internal/protocol"
)

type KnowledgeBaseEditorAuthorizer struct {
	checker authz.Checker
}

func NewKnowledgeBaseEditorAuthorizer(checker authz.Checker) (*KnowledgeBaseEditorAuthorizer, error) {
	if checker == nil {
		return nil, fmt.Errorf("%w: checker is required", ErrUnavailable)
	}
	return &KnowledgeBaseEditorAuthorizer{checker: checker}, nil
}

func (a *KnowledgeBaseEditorAuthorizer) Authorize(
	ctx context.Context,
	authorization protocol.AuthorizationContext,
) (Visibility, error) {
	if a == nil || a.checker == nil || ctx == nil {
		return Visibility{}, ErrUnavailable
	}
	if err := authorization.Validate(); err != nil {
		return Visibility{}, nil
	}
	// Tenant-wide governance is not delegated through an agent/task scope.
	if authorization.AgentID != "" {
		return Visibility{}, nil
	}
	decision, err := a.checker.Check(ctx, authz.CheckRequest{
		User: "user:" + authorization.PrincipalID, Relation: authz.RelationCanEdit,
		Object:               "knowledge_base:" + authorization.KnowledgeBaseID,
		AuthorizationModelID: authorization.AuthorizationModelID, Consistency: authz.ConsistencyHigherConsistency,
	})
	if err != nil {
		return Visibility{}, err
	}
	if !decision.Allowed || decision.AuthorizationModelID != authorization.AuthorizationModelID {
		return Visibility{}, nil
	}
	return Visibility{
		TenantStatus: true, ConnectorSummary: true, ConnectorDetails: true,
		SimulationSummary: true, SimulationDetails: true, AuditReferences: true,
		ResidencyViolations: true,
	}, nil
}

var _ Authorizer = (*KnowledgeBaseEditorAuthorizer)(nil)
