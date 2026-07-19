package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	einotool "github.com/cloudwego/eino/components/tool"

	"github.com/zzqDeco/knote/internal/authz"
	einotools "github.com/zzqDeco/knote/internal/eino/tools"
	"github.com/zzqDeco/knote/internal/identity"
	"github.com/zzqDeco/knote/internal/knowledge/authorized"
	"github.com/zzqDeco/knote/internal/knowledge/authorized/fixture"
	"github.com/zzqDeco/knote/internal/knowledge/kag"
	"github.com/zzqDeco/knote/internal/knowledge/versioned"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository"
	"github.com/zzqDeco/knote/internal/runtime"
)

const (
	permissionedEnabledEnv       = "KNOTE_PERMISSIONED"
	permissionedPrincipalEnv     = "KNOTE_PERMISSIONED_PRINCIPAL"
	permissionedProviderEnv      = "KNOTE_KAG_PERMISSIONED_PROVIDER"
	openFGAEndpointEnv           = "KNOTE_OPENFGA_ENDPOINT"
	openFGAStoreIDEnv            = "KNOTE_OPENFGA_STORE_ID"
	openFGAModelIDEnv            = "KNOTE_OPENFGA_MODEL_ID"
	openFGATimeoutEnv            = "KNOTE_OPENFGA_TIMEOUT"
	openFGAConsistencyEnv        = "KNOTE_OPENFGA_CONSISTENCY"
	permissionedTelemetryPathEnv = "KNOTE_PERMISSIONED_TELEMETRY_PATH"

	permissionedQueryCacheSize   = 64
	permissionedRetrieverVersion = "permissioned-retriever-v1"
	permissionedPromptVersion    = "permissioned-prompt-v1"
	defaultOpenFGATimeout        = 3 * time.Second
	maxIdentityPublicationChecks = 8
)

type permissionedMembershipPublisher interface {
	PublishLatest(context.Context) (identity.MembershipPublicationReceipt, error)
}

type permissionedRuntimeConfig struct {
	Enabled             bool
	Fake                bool
	Principal           string
	IdentityWatermark   string
	Provider            string
	TelemetryPath       string
	OpenFGA             authz.OpenFGAConfig
	Consistency         protocol.ConsistencyPreference
	identity            *permissionedIdentitySession
	membershipPublisher permissionedMembershipPublisher
}

type permissionedApplication struct {
	service               *authorized.Service
	fixture               *fixture.Application
	authorizationProvider runtime.AuthorizationContextProvider
	toolAuthorizationGate *authz.ToolAuthorizationGate
	revisionState         *permissionedRevisionState
	identity              *permissionedIdentitySession
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
		telemetryPath, err := optionalPermissionedTelemetryPath()
		if err != nil {
			return permissionedRuntimeConfig{}, err
		}
		return permissionedRuntimeConfig{
			Enabled: true, Fake: true, Principal: principal, TelemetryPath: telemetryPath,
		}, nil
	}
	if requested != "1" {
		return permissionedRuntimeConfig{}, nil
	}
	telemetryPath, err := optionalPermissionedTelemetryPath()
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
		Enabled: true, Provider: provider,
		TelemetryPath: telemetryPath,
		OpenFGA: authz.OpenFGAConfig{
			Endpoint: endpoint, StoreID: storeID, AuthorizationModelID: modelID,
			Timeout: timeout, Consistency: consistency,
		},
		Consistency: protocolConsistency,
	}, nil
}

func optionalPermissionedTelemetryPath() (string, error) {
	path := strings.TrimSpace(os.Getenv(permissionedTelemetryPathEnv))
	if path != "" && !filepath.IsAbs(path) {
		return "", fmt.Errorf("%s must be an absolute path", permissionedTelemetryPathEnv)
	}
	return path, nil
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
	telemetrySink := newPermissionedTelemetrySink(config.TelemetryPath)
	if config.Fake {
		application, err := fixture.NewApplication(backend, fixture.ApplicationOptions{
			Cache: cache, RetrieverVersion: permissionedRetrieverVersion, PromptVersion: permissionedPromptVersion,
			Telemetry: telemetrySink,
		})
		if err != nil {
			return nil, err
		}
		result := &permissionedApplication{
			service: application.Service, fixture: application,
			authorizationProvider: func(ctx context.Context, sessionID string) (protocol.AuthorizationContext, error) {
				if err := ctx.Err(); err != nil {
					return protocol.AuthorizationContext{}, err
				}
				return fixture.Authorization(config.Principal, sessionID), nil
			},
		}
		result.toolAuthorizationGate, err = newPermissionedToolAuthorizationGate(
			application.Authorizer(), nil, result.AuthorizeProtectedContent,
			newPermissionedToolInvocationDeniedHandler(telemetrySink),
		)
		if err != nil {
			return nil, err
		}
		return result, nil
	}

	loader, err := authorized.NewBundleEvidenceLoader(reader)
	if err != nil {
		return nil, err
	}
	scope, err := loader.CurrentAuthorizationScope(ctx)
	if err != nil {
		return nil, fmt.Errorf("initialize permissioned artifact scope: %w", err)
	}
	identitySession := config.identity
	var identitySnapshot protocol.IdentitySnapshot
	if identitySession == nil {
		identitySession, identitySnapshot, err = loadPermissionedIdentitySession(ctx)
	} else {
		identitySnapshot, err = identitySession.gateway.CurrentSnapshot(ctx, identitySession.authenticated)
	}
	if err != nil || identitySnapshot.TenantID != scope.TenantID {
		return nil, fmt.Errorf("initialize permissioned identity: %w", authorized.ErrProtectedContentUnavailable)
	}
	trustedConfig := config
	trustedConfig.Principal = identitySnapshot.PrincipalID
	trustedConfig.IdentityWatermark = identitySnapshot.Watermark
	revisionState, err := newPermissionedRevisionState(trustedConfig, scope, cache, loader.CurrentAuthorizationScope)
	if err != nil {
		return nil, fmt.Errorf("initialize permissioned authorization revision: %w", err)
	}
	authorizer, err := authz.NewOpenFGA(config.OpenFGA)
	if err != nil {
		return nil, fmt.Errorf("initialize permissioned OpenFGA authorizer: %w", err)
	}
	membershipPublisher := config.membershipPublisher
	if membershipPublisher == nil {
		if identitySession.store == nil {
			return nil, fmt.Errorf("initialize permissioned identity membership publication: %w", authorized.ErrProtectedContentUnavailable)
		}
		membershipPublisher, err = authz.NewIdentityMembershipPublisher(
			identitySession.store,
			authorizer,
			identitySnapshot.TenantID,
			config.OpenFGA.StoreID,
			config.OpenFGA.AuthorizationModelID,
		)
		if err != nil {
			return nil, fmt.Errorf("initialize permissioned identity membership publication: %w", authorized.ErrProtectedContentUnavailable)
		}
	}
	service, err := authorized.New(authorized.Options{
		KAG: backend, Authorizer: authorizer, Loader: loader, Cache: cache,
		FinalAuthorizationGate: identitySession.validate,
		RetrieverVersion:       permissionedRetrieverVersion, PromptVersion: permissionedPromptVersion,
		RetrieveLimit: 20, EvidenceLimit: 8, Traversal: productionTraversalConfig(),
		Telemetry: telemetrySink,
	})
	if err != nil {
		return nil, fmt.Errorf("initialize permissioned query service: %w", err)
	}
	provider := newProductionAuthorizationContextProvider(
		config,
		trustedConfig,
		identitySession,
		membershipPublisher,
		revisionState,
		loader.CurrentAuthorizationScope,
	)
	if _, err := provider(ctx, "session_permissioned_startup"); err != nil {
		return nil, fmt.Errorf("validate permissioned authorization context: %w", err)
	}
	result := &permissionedApplication{
		service: service, authorizationProvider: provider, revisionState: revisionState, identity: identitySession,
	}
	result.toolAuthorizationGate, err = newPermissionedToolAuthorizationGate(
		authorizer, result.validateIdentityAuthorization, result.AuthorizeProtectedContent,
		newPermissionedToolInvocationDeniedHandler(telemetrySink),
	)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func newPermissionedToolAuthorizationGate(
	authorizer authz.Authorizer,
	finalGate func(context.Context, protocol.AuthorizationContext) error,
	resultGate authz.ToolResultGate,
	invocationDenied authz.ToolInvocationDeniedHandler,
) (*authz.ToolAuthorizationGate, error) {
	registry, err := einotools.NewPermissionedAuthorizationManifestRegistry()
	if err != nil {
		return nil, fmt.Errorf("initialize permissioned tool manifest: %w", err)
	}
	gate, err := authz.NewToolAuthorizationGate(authz.ToolAuthorizationGateOptions{
		Authorizer: authorizer, Registry: registry,
		FinalAuthorizationGate: finalGate, ResultGate: resultGate, InvocationDenied: invocationDenied,
	})
	if err != nil {
		return nil, fmt.Errorf("initialize permissioned tool authorization: %w", err)
	}
	return gate, nil
}

func newProductionAuthorizationContextProvider(
	config permissionedRuntimeConfig,
	trustedConfig permissionedRuntimeConfig,
	identitySession *permissionedIdentitySession,
	membershipPublisher permissionedMembershipPublisher,
	revisionState *permissionedRevisionState,
	scopeProvider func(context.Context) (authorized.ArtifactAuthorizationScope, error),
) runtime.AuthorizationContextProvider {
	var issuanceMu sync.Mutex
	return func(ctx context.Context, sessionID string) (protocol.AuthorizationContext, error) {
		if ctx == nil {
			return protocol.AuthorizationContext{}, fmt.Errorf("permissioned authorization requires a context")
		}
		if err := ctx.Err(); err != nil {
			return protocol.AuthorizationContext{}, err
		}
		issuanceMu.Lock()
		defer issuanceMu.Unlock()
		if identitySession == nil || membershipPublisher == nil || revisionState == nil || scopeProvider == nil {
			return protocol.AuthorizationContext{}, authorized.ErrProtectedContentUnavailable
		}
		for range maxIdentityPublicationChecks {
			scope, err := scopeProvider(ctx)
			if err != nil {
				return protocol.AuthorizationContext{}, authorized.ErrProtectedContentUnavailable
			}
			authorization, err := identitySession.authorizationContext(ctx, identity.AuthorizationScope{
				TenantID: scope.TenantID, KnowledgeBaseID: scope.KnowledgeBaseID,
				AuthorizationModelID: config.OpenFGA.AuthorizationModelID, ACLWatermark: scope.ACLWatermark,
				Consistency: config.Consistency,
			}, sessionID)
			if err != nil {
				return protocol.AuthorizationContext{}, authorized.ErrProtectedContentUnavailable
			}
			target := identity.MembershipPublicationTarget{
				TenantID:             scope.TenantID,
				StoreID:              config.OpenFGA.StoreID,
				AuthorizationModelID: config.OpenFGA.AuthorizationModelID,
			}
			receipt, err := membershipPublisher.PublishLatest(ctx)
			if err != nil || receipt.Validate() != nil || receipt.TenantID != target.TenantID ||
				receipt.StoreID != target.StoreID || receipt.AuthorizationModelID != target.AuthorizationModelID {
				return protocol.AuthorizationContext{}, authorized.ErrProtectedContentUnavailable
			}
			if !receipt.Matches(target, authorization.IdentityWatermark) {
				continue
			}
			if err := identitySession.validate(ctx, authorization); err != nil {
				continue
			}
			if err := revisionState.refreshIdentityWatermark(ctx, authorization.IdentityWatermark); err != nil {
				return protocol.AuthorizationContext{}, authorized.ErrProtectedContentUnavailable
			}
			currentConfig := trustedConfig
			currentConfig.IdentityWatermark = authorization.IdentityWatermark
			revision, err := revisionState.currentForScope(ctx, currentConfig, scope)
			if err != nil || authorization.AuthorizationModelID != revision.AuthorizationModelID ||
				authorization.IdentityWatermark != revision.IdentityWatermark ||
				authorization.ACLWatermark != revision.ACLWatermark {
				return protocol.AuthorizationContext{}, authorized.ErrProtectedContentUnavailable
			}
			if err := identitySession.validate(ctx, authorization); err != nil {
				continue
			}
			return authorization, nil
		}
		return protocol.AuthorizationContext{}, authorized.ErrProtectedContentUnavailable
	}
}

func fakeBuildAuthorizationProvider(
	workspace string,
	repo repository.Workspace,
	principal string,
) (runtime.AuthorizationContextProvider, error) {
	if repo == nil {
		return nil, fmt.Errorf("fake build authorization requires a workspace repository")
	}
	return func(ctx context.Context, sessionID string) (protocol.AuthorizationContext, error) {
		if ctx == nil {
			return protocol.AuthorizationContext{}, fmt.Errorf("fake build authorization requires a context")
		}
		if err := ctx.Err(); err != nil {
			return protocol.AuthorizationContext{}, err
		}
		cfg, err := repo.Config(ctx)
		if err != nil {
			return protocol.AuthorizationContext{}, fmt.Errorf("load fake build authorization config: %w", err)
		}
		scope, err := versioned.ResolveMaterializationAuthorizationScope(workspace, cfg)
		if err != nil {
			return protocol.AuthorizationContext{}, fmt.Errorf("resolve fake build authorization scope: %w", err)
		}
		authorization := fixture.Authorization(principal, sessionID)
		authorization.TenantID = scope.TenantID
		authorization.KnowledgeBaseID = scope.KnowledgeBaseID
		authorization.ACLWatermark = scope.ACLWatermark
		if err := authorization.Validate(); err != nil {
			return protocol.AuthorizationContext{}, fmt.Errorf("fake build authorization context: %w", err)
		}
		return authorization, nil
	}, nil
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

func (a *permissionedApplication) ToolAuthorizationGate() *authz.ToolAuthorizationGate {
	if a == nil {
		return nil
	}
	return a.toolAuthorizationGate
}

func (a *permissionedApplication) PrepareFakeBuildAuthorization(authorization protocol.AuthorizationContext) error {
	if a == nil || a.fixture == nil {
		return fmt.Errorf("fake build authorization is unavailable")
	}
	if err := a.fixture.EnsureBuildKnowledgeBaseEditor(authorization); err != nil {
		return fmt.Errorf("fake build authorization denied")
	}
	return nil
}

func (a *permissionedApplication) RefreshAuthorizationScope(ctx context.Context) error {
	if a == nil || a.revisionState == nil {
		return errPermissionedRevisionUnavailable
	}
	return a.revisionState.refreshScope(ctx)
}

func (a *permissionedApplication) Query(
	ctx context.Context,
	request protocol.QueryRequest,
) (authorized.QueryResult, error) {
	if a == nil || a.service == nil {
		return authorized.QueryResult{}, authorized.ErrProtectedContentUnavailable
	}
	if a.revisionState == nil {
		return a.service.Query(ctx, request)
	}
	if err := a.validateIdentityAuthorization(ctx, request.Authorization); err != nil {
		return authorized.QueryResult{}, authorized.ErrProtectedContentUnavailable
	}
	revision, err := a.revisionState.begin(ctx, request.Authorization)
	if err != nil {
		return authorized.QueryResult{}, authorized.ErrProtectedContentUnavailable
	}
	result, err := a.service.Query(ctx, request)
	if err != nil {
		return authorized.QueryResult{}, err
	}
	if err := a.validateIdentityAuthorization(ctx, request.Authorization); err != nil {
		return authorized.QueryResult{}, authorized.ErrProtectedContentUnavailable
	}
	if err := a.revisionState.finish(ctx, revision, permissionedEvidenceResourceIDs(result.Evidence)); err != nil {
		return authorized.QueryResult{}, authorized.ErrProtectedContentUnavailable
	}
	return result, nil
}

func (a *permissionedApplication) ReadDerivedArtifact(
	ctx context.Context,
	authorization protocol.AuthorizationContext,
	resource protocol.ResourceHandle,
) (protocol.EvidenceItem, error) {
	if a == nil || a.service == nil {
		return protocol.EvidenceItem{}, authorized.ErrProtectedContentUnavailable
	}
	if a.revisionState == nil {
		return a.service.ReadDerivedArtifact(ctx, authorization, resource)
	}
	if err := a.validateIdentityAuthorization(ctx, authorization); err != nil {
		return protocol.EvidenceItem{}, authorized.ErrProtectedContentUnavailable
	}
	revision, err := a.revisionState.begin(ctx, authorization)
	if err != nil {
		return protocol.EvidenceItem{}, authorized.ErrProtectedContentUnavailable
	}
	item, err := a.service.ReadDerivedArtifact(ctx, authorization, resource)
	if err != nil {
		return protocol.EvidenceItem{}, err
	}
	if err := a.validateIdentityAuthorization(ctx, authorization); err != nil {
		return protocol.EvidenceItem{}, authorized.ErrProtectedContentUnavailable
	}
	if err := a.revisionState.finish(ctx, revision, permissionedDerivedArtifactResourceIDs(item)); err != nil {
		return protocol.EvidenceItem{}, authorized.ErrProtectedContentUnavailable
	}
	return item, nil
}

func (a *permissionedApplication) AuthorizeProtectedContent(
	ctx context.Context,
	current protocol.AuthorizationContext,
	binding protocol.ProtectedContentBinding,
) error {
	if a == nil || a.service == nil {
		return authorized.ErrProtectedContentUnavailable
	}
	if a.revisionState == nil {
		_, err := a.service.AuthorizeProtectedContent(ctx, current, binding)
		return err
	}
	if err := a.validateIdentityAuthorization(ctx, current); err != nil {
		return authorized.ErrProtectedContentUnavailable
	}
	revision, err := a.revisionState.begin(ctx, current)
	if err != nil {
		return authorized.ErrProtectedContentUnavailable
	}
	if _, err := a.service.AuthorizeProtectedContent(ctx, current, binding); err != nil {
		return err
	}
	if err := a.validateIdentityAuthorization(ctx, current); err != nil {
		return authorized.ErrProtectedContentUnavailable
	}
	if err := a.revisionState.finish(ctx, revision, permissionedBindingResourceIDs(binding)); err != nil {
		return authorized.ErrProtectedContentUnavailable
	}
	return nil
}

func (a *permissionedApplication) validateIdentityAuthorization(
	ctx context.Context,
	authorization protocol.AuthorizationContext,
) error {
	if a == nil || a.identity == nil {
		return nil
	}
	return a.identity.validate(ctx, authorization)
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

func filterPermissionedTools(
	tools []einotool.InvokableTool,
	enabled bool,
	allowed func(string, bool) bool,
) []einotool.InvokableTool {
	out := make([]einotool.InvokableTool, 0, len(tools))
	for _, candidate := range tools {
		if candidate == nil {
			continue
		}
		info, err := candidate.Info(context.Background())
		if err != nil || info == nil || !allowed(info.Name, enabled) {
			continue
		}
		out = append(out, candidate)
	}
	return out
}

func filterPermissionedToolMap(
	tools map[string]einotool.InvokableTool,
	enabled bool,
	allowed func(string, bool) bool,
) map[string]einotool.InvokableTool {
	for name := range tools {
		if !allowed(name, enabled) {
			delete(tools, name)
		}
	}
	return tools
}

func permissionedModelTools(tools []einotool.InvokableTool, enabled bool) []einotool.InvokableTool {
	return filterPermissionedTools(tools, enabled, permissionedModelToolAllowed)
}

func permissionedSlashTools(tools []einotool.InvokableTool, enabled bool) []einotool.InvokableTool {
	return filterPermissionedTools(tools, enabled, permissionedSlashToolAllowed)
}

func permissionedSideEffectToolMap(
	tools map[string]einotool.InvokableTool,
	enabled bool,
) map[string]einotool.InvokableTool {
	return filterPermissionedToolMap(tools, enabled, permissionedSideEffectToolAllowed)
}

func permissionedModelToolAllowed(name string, enabled bool) bool {
	if !enabled {
		return name != einotools.NameEval && name != einotools.NameQuery && name != einotools.NameExplain
	}
	return name == einotools.NameQuery || name == einotools.NameExplain
}

func permissionedSlashToolAllowed(name string, enabled bool) bool {
	if !enabled {
		return permissionedModelToolAllowed(name, false)
	}
	switch name {
	case einotools.NameBuild, einotools.NameCommit, einotools.NameRelease, einotools.NameCheckout:
		return true
	default:
		return false
	}
}

func permissionedSideEffectToolAllowed(name string, enabled bool) bool {
	if !enabled {
		return permissionedModelToolAllowed(name, false)
	}
	switch name {
	case einotools.NameBuild, einotools.NameCommit, einotools.NameRelease, einotools.NameCheckout:
		return true
	default:
		return false
	}
}
