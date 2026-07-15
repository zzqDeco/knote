package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	einotool "github.com/cloudwego/eino/components/tool"

	"github.com/zzqDeco/knote/internal/authz"
	einotools "github.com/zzqDeco/knote/internal/eino/tools"
	"github.com/zzqDeco/knote/internal/knowledge/authorized"
	"github.com/zzqDeco/knote/internal/knowledge/authorized/fixture"
	"github.com/zzqDeco/knote/internal/knowledge/kag"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository"
	"github.com/zzqDeco/knote/internal/runtime"
)

const (
	permissionedEnabledEnv           = "KNOTE_PERMISSIONED"
	permissionedPrincipalEnv         = "KNOTE_PERMISSIONED_PRINCIPAL"
	permissionedIdentityWatermarkEnv = "KNOTE_PERMISSIONED_IDENTITY_WATERMARK"
	permissionedProviderEnv          = "KNOTE_KAG_PERMISSIONED_PROVIDER"
	openFGAEndpointEnv               = "KNOTE_OPENFGA_ENDPOINT"
	openFGAStoreIDEnv                = "KNOTE_OPENFGA_STORE_ID"
	openFGAModelIDEnv                = "KNOTE_OPENFGA_MODEL_ID"
	openFGATimeoutEnv                = "KNOTE_OPENFGA_TIMEOUT"
	openFGAConsistencyEnv            = "KNOTE_OPENFGA_CONSISTENCY"

	permissionedQueryCacheSize   = 64
	permissionedRetrieverVersion = "permissioned-retriever-v1"
	permissionedPromptVersion    = "permissioned-prompt-v1"
	defaultOpenFGATimeout        = 3 * time.Second
)

var permissionedRequestSequence atomic.Uint64

type permissionedRuntimeConfig struct {
	Enabled           bool
	Fake              bool
	Principal         string
	IdentityWatermark string
	Provider          string
	OpenFGA           authz.OpenFGAConfig
	Consistency       protocol.ConsistencyPreference
}

type permissionedApplication struct {
	service               *authorized.Service
	fixture               *fixture.Application
	authorizationProvider runtime.AuthorizationContextProvider
}

func loadPermissionedRuntimeConfig(fake bool) (permissionedRuntimeConfig, error) {
	requested := strings.TrimSpace(os.Getenv(permissionedEnabledEnv))
	if requested != "" && requested != "0" && requested != "1" {
		return permissionedRuntimeConfig{}, fmt.Errorf("%s must be 0 or 1", permissionedEnabledEnv)
	}
	if fake {
		if requested == "1" {
			return permissionedRuntimeConfig{}, fmt.Errorf("%s and KNOTE_KAG_FAKE cannot both be enabled", permissionedEnabledEnv)
		}
		principal, err := permissionedFixturePrincipal()
		if err != nil {
			return permissionedRuntimeConfig{}, err
		}
		return permissionedRuntimeConfig{Enabled: true, Fake: true, Principal: principal}, nil
	}
	if requested != "1" {
		return permissionedRuntimeConfig{}, nil
	}

	principal, err := requiredPermissionedEnv(permissionedPrincipalEnv)
	if err != nil {
		return permissionedRuntimeConfig{}, err
	}
	identityWatermark, err := requiredPermissionedEnv(permissionedIdentityWatermarkEnv)
	if err != nil {
		return permissionedRuntimeConfig{}, err
	}
	provider, err := requiredPermissionedEnv(permissionedProviderEnv)
	if err != nil {
		return permissionedRuntimeConfig{}, err
	}
	endpoint, err := requiredPermissionedEnv(openFGAEndpointEnv)
	if err != nil {
		return permissionedRuntimeConfig{}, err
	}
	storeID, err := requiredPermissionedEnv(openFGAStoreIDEnv)
	if err != nil {
		return permissionedRuntimeConfig{}, err
	}
	modelID, err := requiredPermissionedEnv(openFGAModelIDEnv)
	if err != nil {
		return permissionedRuntimeConfig{}, err
	}
	if _, err := requiredPermissionedEnv(authz.APITokenEnv); err != nil {
		return permissionedRuntimeConfig{}, err
	}

	timeout := defaultOpenFGATimeout
	if value := strings.TrimSpace(os.Getenv(openFGATimeoutEnv)); value != "" {
		timeout, err = time.ParseDuration(value)
		if err != nil || timeout <= 0 {
			return permissionedRuntimeConfig{}, fmt.Errorf("%s must be a positive duration", openFGATimeoutEnv)
		}
	}
	consistency := authz.ConsistencyHigherConsistency
	protocolConsistency := protocol.ConsistencyHigherConsistency
	if value := strings.TrimSpace(os.Getenv(openFGAConsistencyEnv)); value != "" {
		switch value {
		case string(authz.ConsistencyHigherConsistency):
		case string(authz.ConsistencyMinimizeLatency):
			consistency = authz.ConsistencyMinimizeLatency
			protocolConsistency = protocol.ConsistencyMinimizeLatency
		default:
			return permissionedRuntimeConfig{}, fmt.Errorf("%s has unsupported value %q", openFGAConsistencyEnv, value)
		}
	}
	return permissionedRuntimeConfig{
		Enabled: true, Principal: principal, IdentityWatermark: identityWatermark, Provider: provider,
		OpenFGA: authz.OpenFGAConfig{
			Endpoint: endpoint, StoreID: storeID, AuthorizationModelID: modelID,
			Timeout: timeout, Consistency: consistency,
		},
		Consistency: protocolConsistency,
	}, nil
}

func requiredPermissionedEnv(name string) (string, error) {
	value, ok := os.LookupEnv(name)
	if !ok || value == "" || value != strings.TrimSpace(value) {
		return "", fmt.Errorf("%s must contain a non-empty value", name)
	}
	return value, nil
}

func newPermissionedApplication(
	ctx context.Context,
	config permissionedRuntimeConfig,
	backend kag.PrimitiveBackend,
	reader repository.SelectedArtifactReader,
) (*permissionedApplication, error) {
	if !config.Enabled {
		return nil, nil
	}
	cache, err := authorized.NewQueryCache(permissionedQueryCacheSize)
	if err != nil {
		return nil, err
	}
	if config.Fake {
		application, err := fixture.NewApplication(backend, fixture.ApplicationOptions{
			Cache: cache, RetrieverVersion: permissionedRetrieverVersion, PromptVersion: permissionedPromptVersion,
		})
		if err != nil {
			return nil, err
		}
		return &permissionedApplication{
			service: application.Service, fixture: application,
			authorizationProvider: func(ctx context.Context, sessionID string) (protocol.AuthorizationContext, error) {
				if err := ctx.Err(); err != nil {
					return protocol.AuthorizationContext{}, err
				}
				return fixture.Authorization(config.Principal, sessionID), nil
			},
		}, nil
	}

	loader, err := authorized.NewBundleEvidenceLoader(reader)
	if err != nil {
		return nil, err
	}
	if _, err := loader.CurrentAuthorizationScope(ctx); err != nil {
		return nil, fmt.Errorf("initialize permissioned artifact scope: %w", err)
	}
	authorizer, err := authz.NewOpenFGA(config.OpenFGA)
	if err != nil {
		return nil, fmt.Errorf("initialize permissioned OpenFGA authorizer: %w", err)
	}
	service, err := authorized.New(authorized.Options{
		KAG: backend, Authorizer: authorizer, Loader: loader, Cache: cache,
		RetrieverVersion: permissionedRetrieverVersion, PromptVersion: permissionedPromptVersion,
		RetrieveLimit: 20, EvidenceLimit: 8, Traversal: productionTraversalConfig(),
	})
	if err != nil {
		return nil, fmt.Errorf("initialize permissioned query service: %w", err)
	}
	provider := func(ctx context.Context, sessionID string) (protocol.AuthorizationContext, error) {
		if ctx == nil {
			return protocol.AuthorizationContext{}, fmt.Errorf("permissioned authorization requires a context")
		}
		if err := ctx.Err(); err != nil {
			return protocol.AuthorizationContext{}, err
		}
		scope, err := loader.CurrentAuthorizationScope(ctx)
		if err != nil {
			return protocol.AuthorizationContext{}, err
		}
		authorization := protocol.AuthorizationContext{
			Version:  protocol.SecurityContractVersion,
			TenantID: scope.TenantID, KnowledgeBaseID: scope.KnowledgeBaseID,
			PrincipalID: config.Principal, SessionID: sessionID,
			RequestID:            fmt.Sprintf("request_permissioned_%020d", permissionedRequestSequence.Add(1)),
			AuthorizationModelID: config.OpenFGA.AuthorizationModelID,
			IdentityWatermark:    config.IdentityWatermark, ACLWatermark: scope.ACLWatermark,
			Consistency: config.Consistency,
		}
		if err := authorization.Validate(); err != nil {
			return protocol.AuthorizationContext{}, fmt.Errorf("permissioned authorization context: %w", err)
		}
		return authorization, nil
	}
	if _, err := provider(ctx, "session_permissioned_startup"); err != nil {
		return nil, fmt.Errorf("validate permissioned authorization context: %w", err)
	}
	return &permissionedApplication{service: service, authorizationProvider: provider}, nil
}

func productionTraversalConfig() authorized.TraversalConfig {
	return authorized.TraversalConfig{
		Enabled:          true,
		PredicateSources: []protocol.ClaimPredicateSourceKey{protocol.ClaimPredicatePartOf},
		ResourceKinds: []protocol.GraphResourceKind{
			protocol.GraphResourceClaim,
			protocol.GraphResourceEntity,
		},
		Direction: protocol.TraversalOutbound,
		Limits: protocol.TraversalLimits{
			MaxDepth: 3, MaxFrontierWidth: 32, MaxCandidatesPerHop: 32,
			MaxTotalResources: 128, MaxBatchChecks: 32, MaxWallClockMillis: 5_000,
		},
	}
}

func (a *permissionedApplication) AuthorizationContextProvider() runtime.AuthorizationContextProvider {
	if a == nil {
		return nil
	}
	return a.authorizationProvider
}

func (a *permissionedApplication) AuthorizeProtectedContent(
	ctx context.Context,
	current protocol.AuthorizationContext,
	binding protocol.ProtectedContentBinding,
) error {
	if a == nil || a.service == nil {
		return authorized.ErrProtectedContentUnavailable
	}
	_, err := a.service.AuthorizeProtectedContent(ctx, current, binding)
	return err
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

func permissionedFixturePrincipal() (string, error) {
	principal := strings.TrimSpace(os.Getenv(permissionedPrincipalEnv))
	if principal == "" {
		return fixture.Alice, nil
	}
	switch principal {
	case fixture.Alice, fixture.Bob:
		return principal, nil
	default:
		return "", fmt.Errorf("%s must be %q or %q in fake mode", permissionedPrincipalEnv, fixture.Alice, fixture.Bob)
	}
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
