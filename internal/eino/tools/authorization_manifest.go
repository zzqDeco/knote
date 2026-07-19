package tools

import (
	"github.com/zzqDeco/knote/internal/authz"
	"github.com/zzqDeco/knote/internal/protocol"
)

func PermissionedAuthorizationManifests() []protocol.ToolAuthorizationManifest {
	return []protocol.ToolAuthorizationManifest{
		{
			Version: protocol.ToolAuthorizationContractVersion, ToolName: NameBuild, Action: "build",
			Relation: authz.RelationCanEdit, SideEffect: true, ReturnObligation: protocol.ToolReturnNone,
		},
		{
			Version: protocol.ToolAuthorizationContractVersion, ToolName: NameCheckout, Action: "checkout",
			Relation: authz.RelationCanEdit, SideEffect: true, ReturnObligation: protocol.ToolReturnNone,
		},
		{
			Version: protocol.ToolAuthorizationContractVersion, ToolName: NameCommit, Action: "commit",
			Relation: authz.RelationCanEdit, SideEffect: true, ReturnObligation: protocol.ToolReturnNone,
		},
		{
			Version: protocol.ToolAuthorizationContractVersion, ToolName: NameExplain, Action: "explain",
			Relation: authz.RelationCanView, ReturnObligation: protocol.ToolReturnEvidence,
		},
		{
			Version: protocol.ToolAuthorizationContractVersion, ToolName: NameQuery, Action: "query",
			Relation: authz.RelationCanView, ReturnObligation: protocol.ToolReturnEvidence,
		},
		{
			Version: protocol.ToolAuthorizationContractVersion, ToolName: NameRelease, Action: "release",
			Relation: authz.RelationCanEdit, SideEffect: true, ReturnObligation: protocol.ToolReturnNone,
		},
	}
}

func NewPermissionedAuthorizationManifestRegistry() (*protocol.ToolManifestRegistry, error) {
	return protocol.NewToolManifestRegistry(PermissionedAuthorizationManifests())
}
