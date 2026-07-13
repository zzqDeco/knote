package main

import (
	"fmt"
	"os"
	"strings"

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
