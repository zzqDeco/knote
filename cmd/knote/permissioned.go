package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	einotool "github.com/cloudwego/eino/components/tool"

	einotools "github.com/zzqDeco/knote/internal/eino/tools"
	"github.com/zzqDeco/knote/internal/knowledge/authorized/fixture"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/runtime"
)

const permissionedPrincipalEnv = "KNOTE_PERMISSIONED_PRINCIPAL"

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
		if err != nil || info == nil || info.Name == einotools.NameEval || (!enabled && (info.Name == einotools.NameQuery || info.Name == einotools.NameExplain)) {
			continue
		}
		out = append(out, candidate)
	}
	return out
}

func permissionedToolMap(tools map[string]einotool.InvokableTool, enabled bool) map[string]einotool.InvokableTool {
	delete(tools, einotools.NameEval)
	if !enabled {
		delete(tools, einotools.NameQuery)
		delete(tools, einotools.NameExplain)
	}
	return tools
}
