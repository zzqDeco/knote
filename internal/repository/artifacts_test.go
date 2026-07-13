package repository

import (
	"testing"

	"github.com/zzqDeco/knote/internal/protocol"
)

func TestCanonicalArtifactFilesRejectsGraphBindingsOutsideManifestVersions(t *testing.T) {
	resourceID := protocol.ResourceID("res_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	handle := protocol.ResourceHandle{
		ResourceID:              resourceID,
		Type:                    protocol.ResourceDocument,
		TenantID:                "tenant",
		KnowledgeBaseID:         "knowledge-base",
		AuthorizationID:         "document:" + string(resourceID),
		AuthorizationResourceID: resourceID,
		ContentDigest:           protocol.NewContentDigest("body"),
		Versions: protocol.ResourceVersions{
			Source: "source-stale", Content: "content-stale", ACL: "acl-stale",
			Index:      "index_prj_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			Graph:      "graph_prj_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			Projection: "prj_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		},
		ServingState: protocol.ServingActive,
	}
	binding, err := protocol.NewGraphResourceBinding(handle)
	if err != nil {
		t.Fatal(err)
	}
	base := ArtifactSet{
		BundleManifest: protocol.ArtifactBundleManifest{
			ProjectionVersion:           handle.Versions.Projection,
			AuthorizationVersion:        handle.Versions.ACL,
			GraphBindingContractVersion: protocol.GraphBindingContractVersion,
			SourceSnapshot:              protocol.ArtifactSourceSnapshot{Version: handle.Versions.Source},
		},
		GraphBindings: []protocol.GraphResourceBinding{binding},
	}
	tests := []struct {
		name   string
		mutate func(*protocol.ArtifactBundleManifest)
	}{
		{name: "source", mutate: func(value *protocol.ArtifactBundleManifest) { value.SourceSnapshot.Version = "source-current" }},
		{name: "ACL", mutate: func(value *protocol.ArtifactBundleManifest) { value.AuthorizationVersion = "acl-current" }},
		{name: "projection", mutate: func(value *protocol.ArtifactBundleManifest) {
			value.ProjectionVersion = "prj_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			set := base
			test.mutate(&set.BundleManifest)
			if _, err := CanonicalArtifactFiles(set); err == nil {
				t.Fatalf("artifact files accepted graph bindings with a mismatched manifest %s version", test.name)
			}
		})
	}
}
