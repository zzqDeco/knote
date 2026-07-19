package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	einotools "github.com/zzqDeco/knote/internal/eino/tools"
	"github.com/zzqDeco/knote/internal/knowledge/kag"
	"github.com/zzqDeco/knote/internal/knowledge/versioned"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository/local"
	"github.com/zzqDeco/knote/internal/runtime"
	runtimeeino "github.com/zzqDeco/knote/internal/runtime/eino"
	"github.com/zzqDeco/knote/internal/tui"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == identityControlCommand {
		if err := runIdentityControl(context.Background(), os.Args[2:], os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, errIdentityControlRejected)
			os.Exit(1)
		}
		return
	}
	workspace := flag.String("workspace", ".", "workspace path")
	resume := flag.String("resume", "", "session id to resume")
	showVersion := flag.Bool("version", false, "print version")
	flag.Parse()

	if *showVersion {
		fmt.Printf("version=%s commit=%s date=%s\n", version, commit, date)
		return
	}

	rt, events, err := newRuntime(context.Background(), *workspace, *resume)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	program := tea.NewProgram(tui.New(rt, events), tea.WithAltScreen())
	if _, err := program.Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRuntime(ctx context.Context, workspacePath string, resumeID string) (runtime.Runtime, []protocol.Event, error) {
	workspace, err := filepath.Abs(workspacePath)
	if err != nil {
		return nil, nil, err
	}
	if err := validateRuntimeMode(); err != nil {
		return nil, nil, err
	}
	repo := local.New(workspace)
	repoCfg, err := repo.Config(ctx)
	if err != nil {
		return nil, nil, err
	}
	if os.Getenv("KNOTE_KAG_FAKE") == "1" {
		repoCfg.KAG.Fake = true
	}
	repoCfg.Workspace = workspace
	if err := repo.SaveConfig(ctx, repoCfg); err != nil {
		return nil, nil, err
	}
	knowledgeMode := versioned.ModeReal
	if repoCfg.KAG.Fake {
		knowledgeMode = versioned.ModeFake
	}
	permissionedConfig, err := loadPermissionedRuntimeConfig(repoCfg.KAG.Fake)
	if err != nil {
		return nil, nil, err
	}
	if permissionedConfig.Enabled {
		permissionedConfig.residency, err = newPermissionedResidencyBoundary()
		if err != nil {
			return nil, nil, err
		}
		permissionedConfig.audit, err = newPermissionedAuditRecorder(workspace, permissionedConfig.residency)
		if err != nil {
			return nil, nil, err
		}
	}
	kagClient := kag.Client{
		AdapterPath:          repoCfg.KAG.AdapterPath,
		Workspace:            workspace,
		Host:                 repoCfg.KAG.Host,
		Fake:                 repoCfg.KAG.Fake,
		ConfigPath:           repoCfg.KAG.ConfigPath,
		ProjectID:            repoCfg.KAG.ProjectID,
		Namespace:            repoCfg.KAG.Namespace,
		Language:             repoCfg.KAG.Language,
		RuntimeDir:           repoCfg.KAG.RuntimeDir,
		PermissionedProvider: permissionedConfig.Provider,
	}
	if permissionedConfig.residency != nil {
		kagClient.ProcessingResidency = permissionedConfig.residency.AuthorizeKAGProcessing
	}
	knowledgeService := versioned.New(versioned.Options{Workspace: workspace, Repo: repo, Versions: repo, Backend: kagClient, Mode: knowledgeMode})
	permissionedApplication, err := newPermissionedApplication(ctx, permissionedConfig, kagClient, repo)
	if err != nil {
		return nil, nil, err
	}
	var authorizationProvider runtime.AuthorizationContextProvider
	var toolAuthorizationGate einotools.AuthorizationGate
	var modelToolAuthorizationValidator runtimeeino.ToolAuthorizationValidator
	var permissionedQuery einotools.PermissionedQuery
	var protectedContentAuthorizer runtime.ProtectedContentAuthorizer
	var governanceProvider runtime.GovernanceProvider
	var permissionedScopeRefresh func(context.Context) error
	var permissionedSessionRebind func(context.Context, string) error
	var rt *runtime.Manager
	if permissionedApplication != nil {
		authorizationProvider = permissionedApplication.AuthorizationContextProvider()
		permissionedToolAuthorizationGate := permissionedApplication.ToolAuthorizationGate()
		toolAuthorizationGate = permissionedToolAuthorizationGate
		modelToolAuthorizationValidator = permissionedToolAuthorizationGate
		permissionedQuery = func(ctx context.Context, request protocol.QueryRequest) (einotools.PermissionedQueryResult, error) {
			result, err := permissionedApplication.Query(ctx, request)
			if err != nil {
				return einotools.PermissionedQueryResult{}, err
			}
			return einotools.PermissionedQueryResult{
				Answer:          result.Generation.Answer,
				Mode:            result.Generation.Mode,
				EvidencePackage: result.Evidence,
			}, nil
		}
		protectedContentAuthorizer = permissionedApplication.AuthorizeProtectedContent
		governanceProvider, err = newGovernanceProvider(permissionedApplication)
		if err != nil {
			return nil, nil, err
		}
		if !permissionedConfig.Fake {
			permissionedScopeRefresh = permissionedApplication.RefreshAuthorizationScope
			permissionedSessionRebind = func(ctx context.Context, sessionID string) error {
				if rt == nil {
					return fmt.Errorf("permissioned runtime is not initialized")
				}
				return rt.RebindSessionAuthorization(ctx, sessionID)
			}
		}
	}
	sideEffects := runtime.NewSideEffectBridge()
	approvedEinoTools := einotools.ByNameWithOptions(einotools.Options{
		Service:           knowledgeService,
		PermissionedQuery: permissionedQuery,
		SideEffectGate:    func(context.Context, einotools.SideEffectRequest) error { return nil },
		AuthorizationGate: toolAuthorizationGate,
	})
	approvedEinoTools = permissionedSideEffectToolMap(approvedEinoTools, permissionedConfig.Enabled)
	var fakeBuildAuthorization runtime.AuthorizationContextProvider
	if permissionedConfig.Fake {
		fakeBuildAuthorization, err = fakeBuildAuthorizationProvider(workspace, repo, permissionedConfig.Principal)
		if err != nil {
			return nil, nil, err
		}
		baseFakeBuildAuthorization := fakeBuildAuthorization
		fakeBuildAuthorization = func(ctx context.Context, sessionID string) (protocol.AuthorizationContext, error) {
			authorization, err := baseFakeBuildAuthorization(ctx, sessionID)
			if err != nil {
				return protocol.AuthorizationContext{}, err
			}
			if err := permissionedApplication.PrepareFakeBuildAuthorization(authorization); err != nil {
				return protocol.AuthorizationContext{}, err
			}
			return authorization, nil
		}
	}
	allEinoTools := einotools.NewWithOptions(einotools.Options{
		Service:           knowledgeService,
		PermissionedQuery: permissionedQuery,
		AuthorizationGate: toolAuthorizationGate,
		SideEffectGate: newEinoSideEffectGate(
			sideEffects, approvedEinoTools, fakeBuildAuthorization, permissionedScopeRefresh, permissionedSessionRebind,
		),
	})
	slashTools := permissionedSlashTools(allEinoTools, permissionedConfig.Enabled)
	modelTools := permissionedModelTools(allEinoTools, permissionedConfig.Enabled)
	toolExecutor := runtimeeino.NewToolExecutor(slashTools)
	einoRunner, err := newEinoRunner(ctx, repoCfg, modelTools, modelToolAuthorizationValidator)
	if err != nil {
		return nil, nil, err
	}
	capabilities := runtime.DefaultSessionCapabilityProfile()
	if permissionedConfig.Enabled {
		capabilities = runtime.PermissionedSessionCapabilityProfile()
	}
	rt = runtime.New(runtime.Dependencies{
		Workspace:                    workspace,
		Config:                       repoCfg,
		Sessions:                     repo,
		Versions:                     repo,
		WorkspaceRepo:                repo,
		Knowledge:                    knowledgeService,
		Capabilities:                 capabilities,
		RunnerMode:                   runtime.RunnerModeEino,
		EinoRunner:                   einoRunner,
		AuthorizationContextProvider: authorizationProvider,
		ProtectedContentAuthorizer:   protectedContentAuthorizer,
		Governance:                   governanceProvider,
		SideEffects:                  sideEffects,
		ToolExecutor:                 toolExecutor,
		NewSessionID:                 local.NewSessionID,
	})
	events, err := rt.Start(ctx, runtime.StartOptions{ResumeID: resumeID})
	return rt, events, err
}

func validateRuntimeMode() error {
	mode := strings.TrimSpace(os.Getenv("KNOTE_RUNTIME_MODE"))
	if mode == "" || mode == string(runtime.RunnerModeEino) {
		return nil
	}
	return fmt.Errorf("KNOTE_RUNTIME_MODE=%q is not supported; knote uses the Eino runtime only", mode)
}
