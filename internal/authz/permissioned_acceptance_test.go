package authz

import (
	"context"
	"fmt"
	"testing"

	"github.com/zzqDeco/knote/internal/catalog"
	"github.com/zzqDeco/knote/internal/protocol"
)

const (
	permissionedAcceptanceProjectionVersion = "projection-acceptance-v2"
	permissionedAcceptanceModelID           = "01J00000000000000000000000"
)

func TestPermissionedAcceptanceEntityVisibleProtectedClaimHidden(t *testing.T) {
	const invariant = "visible entity must not imply visibility of its protected claim"
	authorizer := permissionedAcceptanceAuthorizer(t, invariant)
	entity := permissionedAcceptanceMetadata(t, invariant, protocol.ResourceEntity,
		"entities/visible", "entity:visible")
	claim := permissionedAcceptanceMetadata(t, invariant, protocol.ResourceClaim,
		"claims/protected", "claim:protected")

	decisions, err := authorizer.BatchCheck(context.Background(), BatchCheckRequest{
		AuthorizationModelID: permissionedAcceptanceModelID,
		Consistency:          ConsistencyHigherConsistency,
		Checks: []BatchCheckItem{
			{CorrelationID: "entity-visible", User: "user:alice", Relation: RelationCanView, Object: entity.AuthorizationObject},
			{CorrelationID: "claim-protected", User: "user:alice", Relation: RelationCanView, Object: claim.AuthorizationObject},
		},
	})
	permissionedAcceptanceNoError(t, invariant, err)
	if len(decisions) != 2 || !decisions[0].Allowed || decisions[1].Allowed {
		permissionedAcceptanceFatalf(t, invariant,
			"policy oracle decisions=%+v, want entity=allow protected_claim=deny", decisions)
	}
	for _, decision := range decisions {
		if decision.AuthorizationModelID != permissionedAcceptanceModelID {
			permissionedAcceptanceFatalf(t, invariant,
				"decision %q returned authz version %q", decision.CorrelationID, decision.AuthorizationModelID)
		}
	}
}

func TestPermissionedAcceptanceDeniedIntermediateClaimBlocksPathParticipation(t *testing.T) {
	const invariant = "denied intermediate claim must block downstream path participation"
	authorizer := permissionedAcceptanceAuthorizer(t, invariant)
	checks := []BatchCheckItem{
		{CorrelationID: "path-source", User: "user:alice", Relation: RelationCanView, Object: "entity:visible"},
		{CorrelationID: "path-claim", User: "user:alice", Relation: RelationCanView, Object: "claim:protected"},
		{CorrelationID: "path-target", User: "user:alice", Relation: RelationCanView, Object: "entity:downstream"},
	}
	decisions, err := authorizer.BatchCheck(context.Background(), BatchCheckRequest{
		AuthorizationModelID: permissionedAcceptanceModelID,
		Consistency:          ConsistencyHigherConsistency,
		Checks:               checks,
	})
	permissionedAcceptanceNoError(t, invariant, err)
	if len(decisions) != len(checks) {
		permissionedAcceptanceFatalf(t, invariant,
			"decision count=%d, want %d", len(decisions), len(checks))
	}
	if !decisions[0].Allowed || decisions[1].Allowed || !decisions[2].Allowed {
		permissionedAcceptanceFatalf(t, invariant,
			"controlled path decisions=%+v, want allow/deny/allow", decisions)
	}
	if permissionedAcceptanceAllAllowed(decisions) {
		permissionedAcceptanceFatalf(t, invariant,
			"path admitted despite denied intermediate decision=%+v", decisions[1])
	}
}

func TestPermissionedAcceptanceReconciliationRemovesStaleTuples(t *testing.T) {
	const invariant = "authorization reconciliation must remove stale tuples and deny old access"
	stale := Tuple{User: "user:alice", Relation: RelationViewer, Object: "document:stale"}
	authorizer, err := NewLocalAuthorizer(permissionedAcceptanceModelID, []Tuple{
		{User: "user:alice", Relation: RelationMember, Object: "organization:acme"},
		{User: "organization:acme", Relation: RelationOrganization, Object: "document:stale"},
		stale,
	})
	permissionedAcceptanceNoError(t, invariant, err)
	permissionedAcceptanceAssertDecision(t, invariant, authorizer, stale.User, stale.Object, true)

	permissionedAcceptanceNoError(t, invariant, authorizer.RemoveTuple(stale))
	permissionedAcceptanceNoError(t, invariant, authorizer.RemoveTuple(stale))
	for _, tuple := range authorizer.Tuples() {
		if tuple == stale {
			permissionedAcceptanceFatalf(t, invariant, "stale tuple remains after reconciliation: %+v", tuple)
		}
	}
	permissionedAcceptanceAssertDecision(t, invariant, authorizer, stale.User, stale.Object, false)
}

func permissionedAcceptanceAuthorizer(t *testing.T, invariant string) *LocalAuthorizer {
	t.Helper()
	tuple := func(user, relation, object string) Tuple {
		return Tuple{User: user, Relation: relation, Object: object}
	}
	tuples := []Tuple{
		tuple("user:alice", RelationMember, "organization:acme"),
		tuple("organization:acme", RelationOrganization, "knowledge_base:acceptance"),
		tuple("user:alice", RelationViewer, "knowledge_base:acceptance"),
		tuple("organization:acme", RelationOrganization, "document:source"),
		tuple("knowledge_base:acceptance", RelationParent, "document:source"),
	}
	for _, object := range []string{"entity:visible", "entity:downstream"} {
		tuples = append(tuples,
			tuple("organization:acme", RelationOrganization, object),
			tuple("document:source", RelationSourceDocument, object),
		)
	}
	tuples = append(tuples,
		tuple("organization:acme", RelationOrganization, "claim:protected"),
		tuple("document:source", RelationSourceDocument, "claim:protected"),
		tuple("entity:visible", RelationSubject, "claim:protected"),
		tuple("entity:downstream", RelationObject, "claim:protected"),
		tuple("user:*", RelationRestricted, "claim:protected"),
	)
	authorizer, err := NewLocalAuthorizer(permissionedAcceptanceModelID, tuples)
	permissionedAcceptanceNoError(t, invariant, err)
	return authorizer
}

func permissionedAcceptanceMetadata(
	t *testing.T,
	invariant string,
	resourceType protocol.ResourceType,
	sourceKey, authorizationObject string,
) catalog.ResourceMetadata {
	t.Helper()
	metadata, err := catalog.NewResourceMetadata(
		catalog.Scope{TenantID: "tenant-acceptance", KnowledgeBaseID: "kb-acceptance"},
		resourceType,
		sourceKey,
		authorizationObject,
		"",
		protocol.NewContentDigest(sourceKey),
		protocol.ResourceVersions{
			Source: "source-acceptance-v2", Content: "content-acceptance-v2",
			ACL: permissionedAcceptanceModelID, Index: "index-acceptance-v2",
			Graph: "graph-acceptance-v2", Projection: permissionedAcceptanceProjectionVersion,
		},
		catalog.SensitivityRestricted,
		"repo:knote",
	)
	permissionedAcceptanceNoError(t, invariant, err)
	return metadata
}

func permissionedAcceptanceAssertDecision(
	t *testing.T,
	invariant string,
	authorizer *LocalAuthorizer,
	user, object string,
	want bool,
) {
	t.Helper()
	decision, err := authorizer.Check(context.Background(), CheckRequest{
		User: user, Relation: RelationCanView, Object: object,
		AuthorizationModelID: permissionedAcceptanceModelID,
		Consistency:          ConsistencyHigherConsistency,
	})
	permissionedAcceptanceNoError(t, invariant, err)
	if decision.Allowed != want {
		permissionedAcceptanceFatalf(t, invariant,
			"decision user=%q object=%q allowed=%t, want %t", user, object, decision.Allowed, want)
	}
}

func permissionedAcceptanceAllAllowed(decisions []Decision) bool {
	for _, decision := range decisions {
		if !decision.Allowed {
			return false
		}
	}
	return true
}

func permissionedAcceptanceNoError(t *testing.T, invariant string, err error) {
	t.Helper()
	if err != nil {
		permissionedAcceptanceFatalf(t, invariant, "unexpected error: %v", err)
	}
}

func permissionedAcceptanceFatalf(t *testing.T, invariant, format string, args ...any) {
	t.Helper()
	prefix := fmt.Sprintf("invariant=%q projection_version=%q authz_version=%q: ",
		invariant, permissionedAcceptanceProjectionVersion, permissionedAcceptanceModelID)
	t.Fatal(prefix + fmt.Sprintf(format, args...))
}
