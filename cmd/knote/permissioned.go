package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	einotool "github.com/cloudwego/eino/components/tool"

	einotools "github.com/zzqDeco/knote/internal/eino/tools"
	"github.com/zzqDeco/knote/internal/knowledge/authorized"
	"github.com/zzqDeco/knote/internal/knowledge/authorized/fixture"
	"github.com/zzqDeco/knote/internal/knowledge/kag"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/runtime"
)

const (
	permissionedPrincipalEnv     = "KNOTE_PERMISSIONED_PRINCIPAL"
	permissionedQueryCacheSize   = 64
	permissionedRetrieverVersion = "fixture-retriever-v1"
	permissionedPromptVersion    = "fixture-prompt-v1"
)

type permissionedApplication struct {
	fixture *fixture.Application
}

func newPermissionedApplication(enabled bool, backend kag.PrimitiveBackend) (*permissionedApplication, error) {
	if !enabled {
		return nil, nil
	}
	cache, err := authorized.NewQueryCache(permissionedQueryCacheSize)
	if err != nil {
		return nil, err
	}
	application, err := fixture.NewApplication(backend, fixture.ApplicationOptions{
		Cache:            cache,
		RetrieverVersion: permissionedRetrieverVersion,
		PromptVersion:    permissionedPromptVersion,
	})
	if err != nil {
		return nil, err
	}
	return &permissionedApplication{fixture: application}, nil
}

func (a *permissionedApplication) AuthorizeProtectedContent(
	ctx context.Context,
	current protocol.AuthorizationContext,
	binding protocol.ProtectedContentBinding,
) error {
	if a == nil || a.fixture == nil {
		return authorized.ErrProtectedContentUnavailable
	}
	return a.fixture.AuthorizeProtectedContent(ctx, current, binding)
}

func (a *permissionedApplication) ApplyRevocation(
	ctx context.Context,
	request authorized.RevocationRequest,
) (authorized.RevocationReport, error) {
	if a == nil || a.fixture == nil {
		return authorized.RevocationReport{}, authorized.ErrRevocationUnavailable
	}
	return a.fixture.Apply(ctx, request)
}

func permissionedPrincipal() (string, error) {
	principal := strings.TrimSpace(os.Getenv(permissionedPrincipalEnv))
	if principal == "" {
		return fixture.Alice, nil
	}
	switch principal {
	case fixture.Alice, fixture.Bob:
		return principal, nil
	default:
		return "", fmt.Errorf("%s must be %q or %q", permissionedPrincipalEnv, fixture.Alice, fixture.Bob)
	}
}

func permissionedAuthorizationProvider(enabled bool) (runtime.AuthorizationContextProvider, error) {
	if !enabled {
		return nil, nil
	}
	principal, err := permissionedPrincipal()
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context, sessionID string) (protocol.AuthorizationContext, error) {
		if err := ctx.Err(); err != nil {
			return protocol.AuthorizationContext{}, err
		}
		return fixture.Authorization(principal, sessionID), nil
	}, nil
}

func permissionedTools(tools []einotool.InvokableTool, enabled bool) []einotool.InvokableTool {
	out := make([]einotool.InvokableTool, 0, len(tools))
	for _, candidate := range tools {
		if candidate == nil {
			continue
		}
		info, err := candidate.Info(context.Background())
		if err != nil || info == nil || !permissionedToolAllowed(info.Name, enabled) {
			continue
		}
		out = append(out, candidate)
	}
	return out
}

func permissionedToolMap(tools map[string]einotool.InvokableTool, enabled bool) map[string]einotool.InvokableTool {
	for name := range tools {
		if !permissionedToolAllowed(name, enabled) {
			delete(tools, name)
		}
	}
	return tools
}

func permissionedToolAllowed(name string, enabled bool) bool {
	if !enabled {
		return name != einotools.NameEval && name != einotools.NameQuery && name != einotools.NameExplain
	}

	// Permissioned ADK registration is fail-closed. These are the authorized
	// query, safe metadata, and confirmation-gated side-effect tools.
	switch name {
	case einotools.NameQuery, einotools.NameExplain,
		einotools.NameVersions,
		einotools.NameBuild, einotools.NameCommit, einotools.NameRelease, einotools.NameCheckout:
		return true
	default:
		return false
	}
}
