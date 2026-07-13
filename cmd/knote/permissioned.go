package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	einotool "github.com/cloudwego/eino/components/tool"

	einotools "github.com/zzqDeco/knote/internal/eino/tools"
	"github.com/zzqDeco/knote/internal/knowledge/authorized/fixture"
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

func permissionedTools(tools []einotool.InvokableTool, enabled bool) []einotool.InvokableTool {
	if enabled {
		return tools
	}
	out := make([]einotool.InvokableTool, 0, len(tools))
	for _, candidate := range tools {
		if candidate == nil {
			continue
		}
		info, err := candidate.Info(context.Background())
		if err != nil || info == nil || info.Name == einotools.NameQuery || info.Name == einotools.NameExplain {
			continue
		}
		out = append(out, candidate)
	}
	return out
}

func permissionedToolMap(tools map[string]einotool.InvokableTool, enabled bool) map[string]einotool.InvokableTool {
	if !enabled {
		delete(tools, einotools.NameQuery)
		delete(tools, einotools.NameExplain)
	}
	return tools
}
